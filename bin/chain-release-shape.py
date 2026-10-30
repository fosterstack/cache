"""Test infrastructure (not product code) for PR 4 "Release", shared by bin/chain-release-wiring-test.sh. Judges for the shape of the Release
stage file, who may hold which credential, the job graph, the one script that verifies, the plainness of the other release scripts, the
list of scripts and the Witness record. Each judge prints `ok` or the list of faults and exits 1 on a fault. The test first proves every
judge on a known-good fixture and on mutated copies (a judge that cannot fail proves nothing), then applies it to the real repository,
which is RED until PR 4 is implemented. Finite grammars and allowlists only, no shell analysis (final PR 1 design, advisor decision b).

  stage FILE          REQ-CHAIN-007-AC1  stage-promote.yml is an ALLOWLIST: on workflow_call only, ONE job `release`, environment release,
                      permissions exactly contents/packages/id-token write, steps exactly checkout, three installs, downloads, the five
                      witnessed steps, uploads.
  credentials FILE    REQ-CHAIN-007-AC2  no env up to and including release-verify; each credential only in the steps listed in WHO.
  others ROOT         REQ-CHAIN-007-AC3  nothing outside stage-promote.yml's release job holds packages write, a credential or the environment.
  graph FILE          REQ-CHAIN-007-AC11 release.yml: the job release needs exactly check, sign, sign-rebuild and sign-check (rule 70 as amended by the Witness move; build through check); rebuild needs build and sign, sign-rebuild build and rebuild; no skip,
                      no secrets, no tag.
  verify FILE         REQ-CHAIN-007-AC4  bin/release-verify.sh is `set -euo pipefail` and then EXACTLY the commands of VERIFY, in order.
  scan FILE JSON      REQ-CHAIN-007-AC6..AC10  a release script is plain: only its listed tools, no other script, no build command, no tag
                      creation, no PATH-like setting, no credential printed (text scan, comments and quotes included; it over-reports).
  listed JSON ROOT    REQ-CHAIN-007-AC10 each release script is a row of chain-scripts.json with its sha256, its tools and its signs value.
  record FILE [VAL..] REQ-CHAIN-007-AC12 no credential name or value, no JWT, no token variable in a Witness envelope (payload decoded).
  metadata FILE       REQ-CHAIN-007-AC13  bin/release-sign.sh makes the metadata in order: the image input, the OpenVEX copy, vex-forms, the manifest (which records the VEX files'
                      sha256 and checks every digest against Build's verified digests.json and items.json), the list, and only then the first signature.
  removed ROOT        REQ-CHAIN-007-AC13 the old authorization machinery is gone.
Modelled on: in-toto-witness docs/attestors/environment.md (what the environment attestor records and what a filter removes) and
docs/tutorials/artifact-policy.md:58-70 (the envelope: base64 payload); PR 3's bin/chain-check-shape.py (the same stage grammar, the same
fixtures); PR 1's chain-scripts.json rows (tools, runs, signs)."""
import base64, hashlib, json, os, re, sys, yaml

# a stored secret or the job token read in any expression syntax (dotted or bracket), or a credential name; used by the credential judges (fail closed on the bracket form too)
CRED_RE = re.compile(r"secrets\s*(\.|\[)|github\s*(\.\s*token|\[\s*['\"]?\s*token)|GH_TOKEN|DOCKERHUB|APK_RELEASE", re.I)
PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
STEPS = ["release-verify", "release-apks", "release-publish", "release-sign", "release-assets", "release-postverify"]   # the last: rule 79 amended, Oct 10
INSTALLS = ["witness", "cosign", "crane"]
RECORD_ENV_VERIFY = "python3 -I bin/chain-verify.py record-env --record witness-release-verify/release-verify-collection.json"      # rc-2 R4: the verify job's own record, checked before it is uploaded
MELANGE_INSTALL = "bash bin/install-build-tools.sh melange"     # REQ-CHAIN-007-AC1 (Astra R4): the one build tool Release needs, for release-sign-apks.sh; the fourth install, after crane
DOWN = {"signed-witness-build", "signed-witness-rebuild", "signed-witness-check", "signed-witness-check-arm64", "check-results", "provenance", "digests", "items", "admission-baseline", "dist", "images", "apk-ubuntu-24.04", "apk-ubuntu-24.04-arm", "apk-compare"}   # the artifacts the verify and release jobs may download: Build's real names (AC17) and the compare job's small result; NEVER a rapk (the owner's rule of Oct 21 2026)
COMPARE_PAIRS = {"apk-ubuntu-24.04": "apks/ubuntu-24.04", "apk-ubuntu-24.04-arm": "apks/ubuntu-24.04-arm", "rapk-ubuntu-24.04": "rapks/ubuntu-24.04", "rapk-ubuntu-24.04-arm": "rapks/ubuntu-24.04-arm", "signed-witness-rapk-ubuntu-24.04": "witness-rapk-ubuntu-24.04", "signed-witness-rapk-ubuntu-24.04-arm": "witness-rapk-ubuntu-24.04-arm"}   # the compare job: Build's apks and Rebuild's, nothing else
VERIFY_PAIRS = {"signed-witness-build": "witness-build", "digests": "witness-build", "items": "witness-build", "admission-baseline": "witness-build", "signed-witness-rebuild": "witness-rebuild",
                "signed-witness-check": "witness-check", "signed-witness-check-arm64": "witness-check/witness-arm64", "check-results": "check-results", "provenance": "provenance",
                "apk-compare": "apk-compare"}   # what release-verify reads, and where (the last: the compare job's result file, the only trace of Rebuild's apks that reaches these jobs)
RELEASE_PAIRS = dict(VERIFY_PAIRS, **{"dist": "dist", "images": "images", "apk-ubuntu-24.04": "apks/ubuntu-24.04", "apk-ubuntu-24.04-arm": "apks/ubuntu-24.04-arm"})   # the release job: the ten above, then what the later steps use; Build's artifacts only
UP = {"release-evidence", "witness-release", "witness-release-verify"}
COMPARE_UPLOAD = {"name": "apk-compare", "path": "apk-compare", "if-no-files-found": "error"}   # the compare job's one upload: a small result file, and a missing file fails the job
COMPARE_RUN = "bash bin/release-compare.sh"
REGISTRY = ("DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "GH_TOKEN")
WHO = {"release-apks": {"APK_RELEASE_SIGNING_KEY"}, "release-publish": set(REGISTRY), "release-sign": set(REGISTRY), "release-assets": {"GH_TOKEN"},
       "release-postverify": {"GH_TOKEN"}}   # read access to the published image only: no registry login, no registry credential (rule 66)
CREDS = {"APK_RELEASE_SIGNING_KEY", "DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "GH_TOKEN"}
# the only `if` a chain job may carry, exactly PR 2's graph judge (bin/chain-test-shape.py): the gate G on build and sign, `!inputs.dry-run` on release (a dry run
# publishes nothing; a skipped predecessor skips release through `needs`, there being no status function in the condition); rebuild and check carry none
GATE_G = "${{ (github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')) || inputs.dry-run == true }}"
IFS_OF = {"build": GATE_G, "sign": GATE_G, "release": "${{ startsWith(github.ref, 'refs/tags/v') && !inputs.dry-run }}"}
CHAIN_JOBS = ["build", "sign", "rebuild", "sign-rebuild", "check", "sign-check", "release"]   # the last stage is Release (the ratified rules' name; Q9)
# the tag rule (REQ-CHAIN-007-AC14, advisor 0383/0386): vX.Y.Z or a release candidate vX.Y.Z-rcN, exactly ^v[0-9]+\.[0-9]+\.[0-9]+-rc[0-9]+$ (the -rc.N form is gone)
TAGLINE = (r'\[\[ "\$\{GITHUB_REF_NAME:-\}" =~ \^v\[0-9\]\+\\\.\[0-9\]\+\\\.\[0-9\]\+\(-rc\[0-9\]\+\)\?\$ \]\] \|\| '
           r'\{ echo "refused at tag: \$\{GITHUB_REF_NAME:-\} is not vX\.Y\.Z or vX\.Y\.Z-rcN" >&2; exit 1; \}')
RC_IF = "${{ !contains(github.ref_name, '-') }}"   # every step after release-verify: a release candidate (a tag with a hyphen) ends after release-verify
VERIFY = [   # bin/release-verify.sh after `set -euo pipefail`: rule 69's order, nothing else (PROPOSED: stage-start takes --rekor-stub for provenance)
    TAGLINE,
    r'python3 bin/chain-verify\.py policy make --template \.github/policy/release-policy\.template\.json --tag "\$GITHUB_REF_NAME" --out policy\.json',
    r"python3 bin/chain-verify\.py stage-start --stage release --previous build --record witness-build/build-collection\.json --digests witness-build/digests\.json --policy policy\.json",
    r"python3 bin/chain-verify\.py bind-items --policy policy\.json --record witness-build/build-collection\.json --items witness-build/items\.json",
    # REQ-CHAIN-007-AC19 (advisor ruling B, Oct 12): the baseline admission chose is a second product of Build's record, bound by name
    r"python3 bin/chain-verify\.py bind-items --policy policy\.json --record witness-build/build-collection\.json --items witness-build/admission-baseline\.json --product admission-baseline\.json",
    r"python3 bin/chain-verify\.py stage-start --stage release --previous sign --record provenance/provenance\.json --digests witness-build/digests\.json --policy policy\.json --rekor-stub provenance/provenance\.rekor\.json",
    r"python3 bin/chain-verify\.py stage-start --stage release --previous rebuild --record witness-rebuild/rebuild-collection\.json --digests witness-build/digests\.json --policy policy\.json",
    # the owner's rule of Oct 21 2026: Rebuild's apks are compared in the compare job (no key, no token); this job reads only its result file, for Build's attested apk digests
    r"python3 bin/chain-verify\.py apk-compare --file apk-compare/apk-compare\.json --digests witness-build/digests\.json",
    r"python3 bin/chain-verify\.py check-list --policy policy\.json --digests witness-build/digests\.json --dir witness-check",
    # ruling G (advisor Oct 12): check-results/govulncheck.json, the file release-sign hands the evidence step, is a product of Check's verified scanners record
    r"python3 bin/chain-verify\.py bind-check --policy policy\.json --record witness-check/witness-scanners/scanners-collection\.json --digests witness-build/digests\.json --file check-results/govulncheck\.json --product check-results/govulncheck\.json",
]
# what each release script may use; `signs` says whether it signs anything; `runs` the other scripts it may start (the chain-scripts.json row)
ROWS = {
    "bin/release-verify.sh":  {"tools": ["python3"], "signs": False, "runs": ["bin/chain-verify.py"]},
    "bin/release-apks.sh":    {"tools": ["bash", "jq", "python3", "trap"], "signs": "other", "runs": ["bin/apk-tool.py", "bin/release-sign-apks.sh"]},   # cache's script signs; Release calls it
    "bin/release-compare.sh": {"tools": ["python3"], "signs": False, "runs": ["bin/release-compare.py"]},   # the compare job's one plain step: a wrapper around the Python file
    "bin/release-compare.py": {"tools": ["make"], "signs": False, "runs": ["bin/apk-tool.py", "bin/chain-verify.py"]},   # no key, no signing, no network: it reads the two apk trees, binds Rebuild's apks to the signed rapk records (chain-verify.py verify and bind) and writes the result file; `make` is the word of `policy make`
    "bin/release-publish.sh": {"tools": ["crane", "jq", "python3", "trap"], "signs": False, "runs": ["bin/release-layout.py"]},   # round 1 B4: the layout is checked first
    "bin/release-layout.py":  {"tools": [], "signs": False, "runs": []},
    "bin/release-sign.sh":    {"tools": ["cosign", "git", "jq", "python3", "trap"], "signs": "other", "runs": ["bin/release-metadata.py", "bin/vendor-provenance.py", "bin/vex-forms.py"]},
    "bin/release-assets.sh":  {"tools": ["gh", "git", "python3"], "signs": False, "runs": ["bin/release-metadata.py"]},   # git reads the tag object; release-metadata.py tag-notes extracts its notes
    "bin/release-postverify.sh": {"tools": ["python3"], "signs": False, "runs": ["bin/release-postverify.py"]},   # rule 79 amended
    "bin/release-postverify.py": {"tools": ["at", "bash", "command", "cosign", "gh", "jq", "just"], "signs": False, "runs": []},   # runs only verify forms, judged first
}
# commands a plain release script must not use unless its row lists them
DENY = ("curl wget nc ncat ssh scp rsync git docker podman buildah buildx kaniko make xargs find eval source trap sudo bash sh dash zsh "
        "python python3 perl ruby node npm yarn pnpm go apko melange cosign crane gh witness jq skopeo oras ko goreleaser tar").split()
KEYWRITE = r'printf %s "\$APK_RELEASE_SIGNING_KEY" > "\$keyfile"'   # the one place the key is written: to a private file, never printed
OLD = ["bin/authorize-acceptance-check.py", "bin/authorize-acceptance-check-test.sh"]


def load(path):
    return yaml.load(open(path), Loader=yaml.BaseLoader)


def has_expression(obj):
    """True when any decoded string (a key or a value, however nested) holds a GitHub expression opener. The protected steps (the whole verify job and every release step up to and
    including release-verify) carry NO expression at all: that closes every spelling of a read of a secret or of the job token (dotted, bracket, whole-context, function-wrapped)
    instead of matching spellings."""
    if isinstance(obj, str):
        return "${{" in obj
    if isinstance(obj, dict):
        return any(has_expression(k) or has_expression(v) for k, v in obj.items())
    if isinstance(obj, list):
        return any(has_expression(x) for x in obj)
    return False


def run_of(step):
    return (step.get("run") or "").strip()


def verify_job(j):
    """REQ-CHAIN-007-AC1 (Astra R6): the verify job holds contents read and id-token write ONLY (Witness mints its certificate from the identity token), no environment,
    no secret, no env, no condition: checkout, the Witness install, the downloads release-verify reads, release-verify under Witness, then uploads."""
    bad = []
    if set(j) - {"runs-on", "permissions", "steps", "name", "timeout-minutes", "needs"}:
        bad.append("verify job: job keys not allowed: %s" % sorted(set(j) - {"runs-on", "permissions", "steps", "name", "timeout-minutes", "needs"}))
    if j.get("needs") not in ("compare", ["compare"]):
        bad.append("verify job: must need exactly the compare job (needs: compare), got %r" % j.get("needs"))
    if j.get("runs-on") != "ubuntu-24.04":
        bad.append("verify job: must run on the GitHub-hosted ubuntu-24.04 runner, got %r" % j.get("runs-on"))
    if j.get("permissions") != {"contents": "read", "id-token": "write"}:
        bad.append("verify job: permissions must be exactly contents read and id-token write: %s" % j.get("permissions"))
    kinds = []
    for s in j.get("steps") or []:
        if set(s) - {"name", "uses", "with", "run"}:
            bad.append("verify job: step keys not allowed (no env, no if): %s" % sorted(set(s) - {"name", "uses", "with", "run"}))
        u, r = s.get("uses", ""), run_of(s)
        if u.startswith("actions/checkout@"):
            kinds.append("checkout")
            if not PIN.match(u.split(" ")[0]) or s.get("with") != {"persist-credentials": "false"}:
                bad.append("verify job: checkout must be digest-pinned with persist-credentials: false only")
        elif u.startswith("actions/download-artifact@"):
            kinds.append("down"); w = s.get("with") or {}
            if not PIN.match(u.split(" ")[0]) or w.get("name") not in DOWN or set(w) != {"name", "path"} or re.match(r"^(bin|\.github|\.|/|\.\.)(/|$)", w.get("path", ".")):
                bad.append("verify job: download-artifact must be digest-pinned, name in the allowlist, an explicit path outside bin/ and .github/: %s" % w)
        elif u.startswith("actions/upload-artifact@"):
            kinds.append("up"); w = s.get("with") or {}
            if not PIN.match(u.split(" ")[0]) or w.get("name") not in UP:
                bad.append("verify job: upload-artifact must be digest-pinned with a name in %s: %s" % (sorted(UP), w))
        elif u:
            bad.append("verify job: uses not allowed: %s" % u)
        elif r == "bash bin/install-scanner.sh witness":
            kinds.append("install:witness")
        elif r == "bash bin/witnessed.sh release-verify bin/release-verify.sh":
            kinds.append("W:release-verify")
        elif r == RECORD_ENV_VERIFY:
            kinds.append("RE")          # rc-2 R4 (Fable): the verify job holds id-token write and uploads its Witness record, so it checks it for a token first, with no if
        else:
            bad.append("verify job: a step that is none of checkout, the Witness install, download, release-verify, its record check or upload: %r" % (r or s.get("name")))
    ds = [i for i, k in enumerate(kinds) if k == "down"]
    ws = [i for i, k in enumerate(kinds) if k == "W:release-verify"]
    ups = [i for i, k in enumerate(kinds) if k == "up"]
    if kinds[:2] != ["checkout", "install:witness"] or not ds or ds != list(range(2, 2 + len(ds))):
        bad.append("verify job: the steps must start with checkout and the install of witness, then the downloads: got %s" % kinds[:4])
    if len(ws) != 1 or ws[0] != 2 + len(ds):
        bad.append("verify job: exactly one release-verify under Witness must follow the downloads directly: %s" % kinds)
    dl = {(x.get("with") or {}).get("name"): (x.get("with") or {}).get("path") for x in j.get("steps") or [] if str(x.get("uses", "")).startswith("actions/download-artifact@")}
    for nm, want in (("signed-witness-check", "witness-check"), ("admission-baseline", "witness-build"), ("check-results", "check-results"), ("signed-witness-check-arm64", "witness-check/witness-arm64")):
        if dl.get(nm) != want:
            bad.append("verify job: artifact %s must be downloaded to %s (where release-verify reads it), got %r" % (nm, want, dl.get(nm)))
    res = [i for i, k in enumerate(kinds) if k == "RE"]
    if len(ws) != 1 or res != [ws[0] + 1]:
        bad.append("verify job: right after release-verify the job must check its own Witness record for a token (%s, no if), exactly once: %s" % (RECORD_ENV_VERIFY, kinds))
    if not ups or ups != list(range(len(kinds) - len(ups), len(kinds))):
        bad.append("verify job: only uploads may follow the record check, and there must be at least one")
    upl = [(x.get("with") or {}) for x in j.get("steps") or [] if str(x.get("uses", "")).startswith("actions/upload-artifact@")]
    if upl != [{"name": "witness-release-verify", "path": "witness-release-verify", "if-no-files-found": "error"}]:
        bad.append("verify job: its one upload must be exactly name witness-release-verify, path witness-release-verify and if-no-files-found error (the Witness record of release-verify; a missing record fails the job; the release job's own upload is witness-release): %s" % upl)
    got = sorted((((x.get("with") or {}).get("name")), ((x.get("with") or {}).get("path"))) for x in j.get("steps") or [] if str(x.get("uses", "")).startswith("actions/download-artifact@"))
    if got != sorted(VERIFY_PAIRS.items()):
        bad.append("verify job: its downloads must be exactly these ten artifact/path pairs, each once and spelled exactly (the action trims whitespace from a path, so nothing else may reach the uploaded directory): %s" % got)
    if has_expression(j.get("steps")):
        bad.append("verify job: no step may hold an expression (${{ }}): a protected step carries no expression and no explicit credential binding; the checkout action's default token use and Witness's identity token are token uses that no expression or binding in these steps accounts for")
    return bad


def compare_job(j):
    """The owner's rule of Oct 21 2026 (ops/docs/ratify/2026-10-21-signer-builder-separate-jobs.md): the comparison of Build's and Rebuild's apks runs in a job with no secrets, no
    publish permission and no identity token: contents read ONLY (an id-token can mint a signing certificate), no environment, no env, no needs, no condition. Its steps are
    exactly: the checkout, the six downloads (Build's two apk artifacts, Rebuild's two rapk artifacts and the two signed rapk records, each to its fixed path), ONE plain step `bash bin/release-compare.sh` (not
    under Witness: Witness signs through the identity token) and one upload of the small result apk-compare, which fails the job when the file is missing. No build script runs here."""
    bad = []
    allowed = {"runs-on", "permissions", "steps", "name", "timeout-minutes"}
    if set(j) - allowed:
        bad.append("compare job: job keys not allowed (no environment, no env, no needs, no if, no container): %s" % sorted(set(j) - allowed))
    if j.get("runs-on") != "ubuntu-24.04":
        bad.append("compare job: must run on the GitHub-hosted ubuntu-24.04 runner, got %r" % j.get("runs-on"))
    if j.get("permissions") != {"contents": "read"}:
        bad.append("compare job: permissions must be exactly contents read (no id-token, no write): %s" % j.get("permissions"))
    kinds, downs = [], []
    for st in j.get("steps") or []:
        if set(st) - {"name", "uses", "with", "run"}:
            bad.append("compare job: step keys not allowed (no env, no if): %s" % sorted(set(st) - {"name", "uses", "with", "run"}))
        u, r, w = st.get("uses", ""), run_of(st), st.get("with") or {}
        if u.startswith("actions/checkout@"):
            kinds.append("checkout")
            if not PIN.match(u.split(" ")[0]) or w != {"persist-credentials": "false"}:
                bad.append("compare job: checkout must be digest-pinned with persist-credentials: false only")
        elif u.startswith("actions/download-artifact@"):
            kinds.append("down"); downs.append((w.get("name"), w.get("path")))
            if not PIN.match(u.split(" ")[0]) or set(w) != {"name", "path"}:
                bad.append("compare job: download-artifact must be digest-pinned with a name and a path only: %s" % w)
        elif u.startswith("actions/upload-artifact@"):
            kinds.append("up")
            if not PIN.match(u.split(" ")[0]) or w != COMPARE_UPLOAD:
                bad.append("compare job: its one upload must be digest-pinned and exactly %s: %s" % (COMPARE_UPLOAD, w))
        elif u:
            bad.append("compare job: uses not allowed: %s" % u)
        elif r == COMPARE_RUN:
            kinds.append("compare")
        else:
            bad.append("compare job: a step that is none of checkout, download, `%s` or the upload (no build script, no Witness, no secret): %r" % (COMPARE_RUN, r or st.get("name")))
    if kinds != ["checkout"] + ["down"] * 6 + ["compare", "up"]:
        bad.append("compare job: the steps must be exactly the checkout, six downloads (Build's two apk artifacts, Rebuild's two rapk artifacts and the two signed rapk records Sign signed), the comparison and the upload, got %s" % kinds)
    if sorted(x for x in downs if x[0] is not None) != sorted(COMPARE_PAIRS.items()):
        bad.append("compare job: its downloads must be exactly these six artifact/path pairs (Build's apks, Rebuild's apks and the signed rapk records), each once: %s" % sorted(downs, key=str))
    if has_expression(j.get("steps")):
        bad.append("compare job: no step may hold an expression (${{ }}): it holds no secret, no token and no condition")
    return bad


def stage(path):
    d, bad = load(path), []
    on = d.get("on") or {}
    if not (isinstance(on, dict) and set(on) == {"workflow_call"}):
        bad.append("on: must be exactly workflow_call: %s" % on)
    if set(d) - {"name", "on", "permissions", "jobs"}:
        bad.append("workflow keys not allowed: %s" % sorted(set(d) - {"name", "on", "permissions", "jobs"}))
    jobs = d.get("jobs") or {}
    if list(jobs) != ["compare", "verify", "release"]:
        return bad + ["exactly three jobs named compare, verify and release (in this order) are required, found %s" % list(jobs)]
    bad += compare_job(jobs["compare"])
    bad += verify_job(jobs["verify"])
    j = jobs["release"]
    # REQ-CHAIN-007-AC1 (Astra R6): the release job starts only after the verify job passed, and not at all for a release candidate
    nd = j.get("needs")
    if nd != ["compare", "verify"]:
        bad.append("the release job must need exactly the compare and the verify job (needs: [compare, verify]), got %r" % nd)
    if j.get("if") != RC_IF:
        bad.append("the release job must carry exactly the job-level if %s (a release candidate never enters the release environment), got %r" % (RC_IF, j.get("if")))
    if set(j) - {"runs-on", "permissions", "steps", "name", "environment", "timeout-minutes", "needs", "if"}:
        bad.append("job keys not allowed: %s" % sorted(set(j) - {"runs-on", "permissions", "steps", "name", "environment", "timeout-minutes", "needs", "if"}))
    if j.get("runs-on") != "ubuntu-24.04":
        bad.append("release must run on the GitHub-hosted ubuntu-24.04 runner, got %r" % j.get("runs-on"))
    if j.get("environment") != "release":
        bad.append("the job must be in the environment named release, got %r" % j.get("environment"))
    if j.get("permissions") != {"contents": "write", "packages": "write", "id-token": "write"}:
        bad.append("permissions must be exactly contents, packages and id-token write: %s" % j.get("permissions"))
    kinds = []
    for s in j.get("steps") or []:
        nk = len(kinds)
        if set(s) - {"name", "uses", "with", "run", "env", "if"}:
            bad.append("step keys not allowed: %s" % sorted(set(s) - {"name", "uses", "with", "run", "env", "if"}))
        u, r = s.get("uses", ""), run_of(s)
        if u.startswith("actions/checkout@"):
            kinds.append("checkout")
            if not PIN.match(u.split(" ")[0]) or s.get("with") != {"persist-credentials": "false"}:
                bad.append("checkout must be digest-pinned with persist-credentials: false only")
        elif u.startswith("actions/download-artifact@"):
            kinds.append("down"); w = s.get("with") or {}
            if not PIN.match(u.split(" ")[0]) or w.get("name") not in DOWN or set(w) != {"name", "path"} or w.get("path", ".") != w.get("path", ".").strip() or re.match(r"^(bin|\.github|\.|/|\.\.)(/|$)", w.get("path", ".").strip()):
                bad.append("download-artifact must be digest-pinned, name in %s, an explicit path with no surrounding whitespace (the action trims it) outside bin/ and .github/: %s" % (sorted(DOWN), w))
        elif u.startswith("actions/upload-artifact@"):
            kinds.append("up"); w = s.get("with") or {}
            if not PIN.match(u.split(" ")[0]) or w.get("name") not in UP:
                bad.append("upload-artifact must be digest-pinned with a name in %s: %s" % (sorted(UP), w))
        elif u:
            bad.append("uses not allowed in the Release stage: %s" % u)
        elif r in ["bash bin/install-scanner.sh " + t for t in INSTALLS]:   # the form the closed stage grammar accepts (bash PATH ARGS), as Build, Sign and Check run it
            kinds.append("install:" + r.split()[-1])
        elif r == MELANGE_INSTALL:
            kinds.append("install:melange")
        elif re.fullmatch(r"bash bin/witnessed\.sh (release-[a-z]+) bin/\1\.sh", r):
            kinds.append("W:" + r.split()[2])
        elif re.fullmatch(r"python3 -I bin/chain-verify\.py record-env --record witness-(release-[a-z]+)/\1-collection\.json", r):   # rc-2 R4: the Release job checks its own six Witness records for a token before they are uploaded (REQ-CHAIN-007-AC12)
            kinds.append("RE:" + r.split()[-1].split("/")[0][len("witness-"):])
        else:
            bad.append("a step that is none of checkout, install, download, witnessed or upload: %r" % (r or s.get("name")))
        want_if = RC_IF if kinds and kinds[-1][:2] in ("W:", "RE") and kinds[-1] not in ("W:release-verify", "RE:release-verify") else None
        if len(kinds) > nk and s.get("if") != want_if:   # nk: kinds before this step; only a step that was classified is judged for its if
            bad.append("step %r must carry %s, found %r (a release candidate ends after release-verify; release-verify and every non-Witness step carry no if)"
                       % (r or u, ("exactly the if " + want_if) if want_if else "no if", s.get("if")))
    want = ["checkout"] + ["install:" + t for t in INSTALLS] + ["install:melange"]
    ds = [i for i, k in enumerate(kinds) if k == "down"]
    ws = [k for k in kinds if k.startswith("W:")]
    ups = [i for i, k in enumerate(kinds) if k == "up"]
    if kinds[:5] != want:
        bad.append("steps must start with checkout and the installs of witness, cosign, crane, melange: got %s" % kinds[:5])
    if not ds or ds != list(range(5, 5 + len(ds))):
        bad.append("the downloads must follow the installs directly and all come before Witness starts (rule 68)")
    # REQ-CHAIN-007-AC16: Check's two uploads meet where bin/chain-verify.py check-list reads them: witness-check/ holds witness-scanners, witness-acceptance and
    # witness-runtime (artifact witness-check), and the arm64 leg's separate artifact witness-check-arm64 lands in witness-check/witness-arm64/
    dl = {(x.get("with") or {}).get("name"): (x.get("with") or {}).get("path") for x in j.get("steps") or [] if str(x.get("uses", "")).startswith("actions/download-artifact@")}
    rgot = sorted((((x.get("with") or {}).get("name")), ((x.get("with") or {}).get("path"))) for x in j.get("steps") or [] if str(x.get("uses", "")).startswith("actions/download-artifact@"))
    if rgot != sorted(RELEASE_PAIRS.items()):
        bad.append("the release job: its downloads must be exactly these fourteen artifact/path pairs, each once and spelled exactly (the action trims whitespace from a path, and the job's upload holds the Witness record directories): %s" % rgot)
    if dl.get("signed-witness-check") != "witness-check":
        bad.append("artifact signed-witness-check must be downloaded to witness-check, got %r" % dl.get("signed-witness-check"))
    if dl.get("admission-baseline") != "witness-build":
        bad.append("artifact admission-baseline must be downloaded to witness-build (where release-verify binds it and release-sign reads it), got %r" % dl.get("admission-baseline"))
    if dl.get("check-results") != "check-results":
        bad.append("artifact check-results must be downloaded to check-results (where release-verify binds govulncheck.json and release-sign reads it), got %r" % dl.get("check-results"))
    if dl.get("signed-witness-check-arm64") != "witness-check/witness-arm64":
        bad.append("artifact signed-witness-check-arm64 must be downloaded to witness-check/witness-arm64 (where check-list reads the arm64 record), got %r" % dl.get("signed-witness-check-arm64"))
    if ws != ["W:" + s for s in STEPS]:
        bad.append("the witnessed steps must be exactly %s, in this order, found %s" % (STEPS, [w[2:] for w in ws]))
    last_w = max((i for i, k in enumerate(kinds) if k.startswith("W:")), default=-1)
    first_w = min((i for i, k in enumerate(kinds) if k.startswith("W:")), default=-1)
    if first_w >= 0 and any(not k.startswith("W:") for k in kinds[first_w:last_w + 1]):
        bad.append("between the first and the last Witness step there must be Witness steps only (an install, a download or an upload in between is refused): %s" % kinds[first_w:last_w + 1])
    if any(k.startswith("install:") for k in kinds[5:]):
        bad.append("between the checkout and the downloads exactly the four installs are allowed, and no install after them: %s" % kinds)
    after = kinds[last_w + 1:]
    if after[:len(STEPS)] != ["RE:" + s for s in STEPS]:
        bad.append("right after the witnessed steps the Release job must check each of its own six Witness records for a token (python3 -I bin/chain-verify.py record-env --record witness-STEP/STEP-collection.json, REQ-CHAIN-007-AC12), exactly %s in this order, found %s" % (STEPS, [k[3:] for k in after if k.startswith("RE:")]))
    if any(k != "up" for k in after[len(STEPS):]) or not ups:
        bad.append("only uploads may follow the witnessed steps and their record checks, and there must be at least one")
    text = open(path).read()
    if re.search(r"docker\s+login|build-push|buildx|goreleaser|\bgo build\b", text):
        bad.append("a registry login or a build command appears in the stage file")
    return bad


def j_names_credential(j):
    blob = yaml.dump(j.get("steps") or [])
    return any(st.get("env") is not None for st in (j.get("steps") or [])) or bool(CRED_RE.search(blob) or re.search(r"environment", blob + " " + str(j.get("environment") or "")))


def credentials(path):
    jobs = load(path).get("jobs") or {}
    vj = jobs.get("verify")
    bad, seen_verify = [], False
    if vj is None:
        bad.append("no verify job found")
    elif j_names_credential(vj) or has_expression(vj.get("steps")):
        bad.append("a step up to release-verify has an env or names a secret or token: the verify job must hold no credential (it holds contents read and id-token write only)")
    cj = jobs.get("compare")
    if cj is None:
        bad.append("no compare job found")
    elif j_names_credential(cj) or has_expression(cj.get("steps")) or (cj.get("permissions") or {}).get("id-token"):
        bad.append("compare job: it must hold no credential, no environment and no identity token (the comparison of Rebuild's apks runs without a key)")
    j = jobs.get("release") or {}
    for s in j.get("steps") or []:
        r, env = run_of(s), s.get("env")
        name = r.split()[2] if r.startswith("bash bin/witnessed.sh ") and len(r.split()) > 3 else None
        blob = yaml.dump(s)
        if not seen_verify:
            if env is not None or CRED_RE.search(blob) or has_expression(s):
                bad.append("a step up to release-verify has an env or names a secret or token: %s" % (r or s.get("uses", "")))
            seen_verify = name == "release-verify"
            continue
        if name is None:
            if env is not None or CRED_RE.search(blob):
                bad.append("only the witnessed steps may carry an env or a secret: %s" % (r or s.get("uses", "")))
            continue
        want = WHO.get(name, set())
        got = set((env or {}).keys())
        if got != want:
            bad.append("%s must get exactly the credentials %s, got %s" % (name, sorted(want), sorted(got)))
        for k, v in (env or {}).items():
            ok = v == ("${{ github.token }}" if k == "GH_TOKEN" else "${{ secrets.%s }}" % k)
            if k in CREDS and not ok:
                bad.append("%s in %s must be one whole read of its own secret, got %r" % (k, name, v))
    if not seen_verify:
        bad.append("no release-verify step found")
    return bad


def others(root):
    bad = []
    wd = os.path.join(root, ".github/workflows")
    for f in sorted(os.listdir(wd)):
        if not f.endswith((".yml", ".yaml")) or f == "stage-promote.yml":
            continue
        t = open(os.path.join(wd, f)).read()
        for pat, what in ((r"DOCKERHUB_TOKEN\b|APK_RELEASE_SIGNING_KEY", "a release credential"), (r"environment:\s*release\b", "the release environment")):
            if re.search(pat, t):
                bad.append("%s names %s" % (f, what))
        if f.startswith("stage-") and re.search(r"packages:\s*write|secrets\.|secrets:\s*inherit", t):
            bad.append("%s holds packages write or a secret: only the release job may" % f)
    rp = os.path.join(wd, "release.yml")
    if os.path.exists(rp):
        d = load(rp)
        wp = d.get("permissions")
        if isinstance(wp, dict) and any(v == "write" and k in ("packages", "id-token", "contents") for k, v in wp.items()):
            bad.append("release.yml grants write at the workflow level: %s" % wp)
        for n, j in (d.get("jobs") or {}).items():
            uses = j.get("uses", "")
            if "stage-" in uses and ("secrets" in j):
                bad.append("job %s passes secrets to a stage call" % n)
            p = j.get("permissions") or {}
            if "stage-" in uses and not uses.endswith("stage-promote.yml") and isinstance(p, dict) and p.get("packages") == "write":
                bad.append("job %s grants packages write: only the release job may" % n)
        if re.search(r"DOCKERHUB_TOKEN\b|APK_RELEASE_SIGNING_KEY", open(rp).read()):
            bad.append("release.yml names a release credential")
    return bad


def graph(path):
    d, bad = load(path), []
    jobs = d.get("jobs") or {}
    if "release" not in jobs:
        bad.append("release.yml has no job release: the last job is named release (the ratified rules' name, Q9), found %s" % list(jobs))
    for n in CHAIN_JOBS[:-1]:
        if n not in jobs:
            bad.append("release.yml has no job %s" % n)
    if bad:
        return bad
    p = jobs["release"]
    needs = p.get("needs", [])
    needs = {needs} if isinstance(needs, str) else set(needs)
    if needs != {"check", "sign", "sign-rebuild", "sign-check"}:   # rule 70 as amended by the Witness move: Sign signs Build's records, sign-rebuild Rebuild's, sign-check Check's; build is reached through check
        bad.append("the release job must need exactly check, sign, sign-rebuild and sign-check (rule 70 as amended by the Witness move; it reaches build through check and rebuild through sign-rebuild), found %s" % sorted(needs))
    for who, want in (("rebuild", {"build", "sign"}), ("sign-rebuild", {"build", "rebuild"}), ("sign-check", {"build", "check"})):
        got = jobs[who].get("needs", [])
        got = {got} if isinstance(got, str) else set(got)
        if got != want:
            bad.append("%s must need exactly %s, found %s" % (who, " and ".join(sorted(want)), sorted(got)))
    if p.get("uses") != "./.github/workflows/stage-promote.yml":
        bad.append("the release job must call ./.github/workflows/stage-promote.yml")
    if p.get("permissions") != {"contents": "write", "packages": "write", "id-token": "write"}:
        bad.append("the release job's permissions must be exactly contents, packages and id-token write: %s" % p.get("permissions"))
    for n in CHAIN_JOBS:
        j = jobs[n]
        if str(j.get("if", "")).strip() != IFS_OF.get(n, ""):
            bad.append("job %s must carry %s, found %r (the one allowed gate: a status function such as always() or !cancelled() lets release run after a failed predecessor)"
                       % (n, "exactly the if %s" % IFS_OF[n] if n in IFS_OF else "no if", j.get("if")))
        if "continue-on-error" in j or "secrets" in j:
            bad.append("job %s has continue-on-error or secrets" % n)
    # the `decide` job is the CI patch tag (REQ-REL-009: a job that holds no id-token and cuts no tag since handoff 0713 P8) and is not Release
    rest = json.dumps({n: j for n, j in jobs.items() if n != "decide"})
    if re.search(r"git tag|git push|create-release|gh release create", rest):
        bad.append("release.yml creates a tag or a release outside the decide job (the CI patch tag): Release creates no tag")
    return bad


def verify(path):
    bad = []
    lines = [l.rstrip() for l in open(path).read().split("\n") if l.strip() and not l.strip().startswith("#")]
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    if not lines or lines[0].strip() != "set -euo pipefail":
        bad.append("the script must start with set -euo pipefail")
    lines = lines[1:] if lines else []
    if len(lines) != len(VERIFY):
        bad.append("the script has %d commands, %d are required: tag, policy, build, sign, rebuild, check (rule 69's order)" % (len(lines), len(VERIFY)))
    for i, rx in enumerate(VERIFY):
        if i < len(lines) and not re.fullmatch(rx, lines[i].strip()):
            bad.append("command %d is not the pinned form: %s" % (i + 1, lines[i].strip()[:110]))
    return bad


def scan(path, jsonpath):
    if not os.path.exists(path):
        return ["missing: %s" % path]
    rel = "bin/" + os.path.basename(path)
    row = ROWS.get(rel, {"tools": [], "runs": []})
    rows = {r["path"]: r for r in json.load(open(jsonpath)).get("scripts", [])} if os.path.exists(jsonpath) else {}
    tools = set(rows.get(rel, row).get("tools", row["tools"]))
    runs = set(rows.get(rel, row).get("runs", row["runs"]))
    text, bad = open(path).read(), []
    for n, l in enumerate(text.split("\n"), 1):
        if n == 1 and l.startswith("#!"):
            continue
        bare = re.sub(r"\b(docker\.io|ghcr\.io)\b|\bpolicy make\b", " ", l)   # registry host names and the one subcommand are not commands
        for w in DENY:
            if w not in tools and re.search(r"(?<![\w./$-])" + re.escape(w) + r"(?![\w-])", bare):
                bad.append("%s:%d uses %r which the row does not list" % (os.path.basename(path), n, w))
        for m in re.finditer(r"(?<![\w.$-])((?:\./)?(?:[\w.-]+/)+[\w.-]+\.(?:sh|py))\b", l):
            p = m.group(1).lstrip("./")
            if p != rel and p not in runs:
                bad.append("%s:%d starts another script: %s" % (os.path.basename(path), n, p))
        if re.search(r"\b(PATH|BASH_ENV|ENV|LD_[A-Z_]+|PYTHON[A-Z_]*|NODE_OPTIONS)=", l):
            bad.append("%s:%d sets a PATH-like variable" % (os.path.basename(path), n))
        if re.search(r"\bset\s+-\w*x|xtrace", l):
            bad.append("%s:%d turns on tracing (it would print credentials)" % (os.path.basename(path), n))
        if re.search(r"\b(echo|printf|cat|tee)\b[^;&|]*\$\{?(%s)\b" % "|".join(sorted(CREDS)), l) and not re.fullmatch(KEYWRITE, l.strip()):
            bad.append("%s:%d prints a credential" % (os.path.basename(path), n))
        if re.search(r"melange\s+build|apko\s+build|go\s+build|docker\s+build|buildx", l):
            bad.append("%s:%d is a build command: Release builds nothing" % (os.path.basename(path), n))
        if re.search(r"git\s+(tag|push)|git/(refs|tags)", l) or (re.search(r"gh\s+release\s+create", l) and "--verify-tag" not in l):
            bad.append("%s:%d creates a tag (a release only with --verify-tag)" % (os.path.basename(path), n))
        if re.search(r"tlog-upload=false|--insecure-ignore-tlog|--skip-confirmation=false", l):
            bad.append("%s:%d turns the transparency log off" % (os.path.basename(path), n))
    return bad


def listed(jsonpath, root):
    if not os.path.exists(jsonpath):
        return ["missing: %s" % jsonpath]
    rows, bad = {r["path"]: r for r in json.load(open(jsonpath)).get("scripts", [])}, []
    for p, want in list(ROWS.items()) + [("bin/witnessed.sh", None)]:
        r = rows.get(p)
        if r is None:
            bad.append("%s is not listed in chain-scripts.json" % p); continue
        f = os.path.join(root, p)
        if not os.path.exists(f):
            bad.append("%s is listed but missing" % p); continue
        if hashlib.sha256(open(f, "rb").read()).hexdigest() != r.get("sha256"):
            bad.append("%s: the sha256 in chain-scripts.json is not the file's" % p)
        if want is None:
            continue
        if sorted(r.get("tools", [])) != sorted(want["tools"]):
            bad.append("%s must list exactly the tools %s, lists %s" % (p, want["tools"], r.get("tools")))
        if r.get("signs") != want["signs"]:
            bad.append("%s must be listed with signs: %s, is %r" % (p, want["signs"], r.get("signs")))
        if want["signs"] == "other" and not r.get("reason"):
            bad.append("%s signs and must carry a reason" % p)
        if sorted(r.get("runs", [])) != sorted(want["runs"]):
            bad.append("%s may start exactly %s, lists %s" % (p, want["runs"], r.get("runs")))
    return bad


def record(path, values):
    bad, raw = [], open(path).read()
    try:
        env = json.loads(raw)
        payload = base64.b64decode(env["payload"]).decode("utf8")
        json.loads(payload)
        text = raw + "\n" + payload
    except Exception:
        return ["not a DSSE envelope with a base64 payload"]
    for n in sorted(CREDS | {"ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_RUNTIME_TOKEN", "SIGSTORE_ID_TOKEN"}):
        if n in text:
            bad.append("the record names %s" % n)
    for v in values:
        if v and v in text:
            bad.append("the record holds a credential value")
    if re.search(r"eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]*", text):
        bad.append("the record holds a compact JWT")
    return bad


def metadata(path):
    """REQ-CHAIN-007-AC13 (advisor 0386 item 2, cache-ce): the VEX and CSAF files are generated BEFORE the signed manifest and before release-files.sha256, the manifest records their
    sha256, the vex-forms input is made from Build's verified digests and items, and nothing is signed before all of it exists."""
    lines = [l.strip() for l in open(path).read().split("\n") if l.strip() and not l.strip().startswith("#")]
    def at(pat, start=0):
        return next((i for i in range(start, len(lines)) if re.search(pat, lines[i])), None)
    marks = {"images": at(r"release-metadata\.py images "), "cp": at(r"^cp \.vex/fosterstack-cache\.openvex\.json release-metadata/"), "vex": at(r"python3 bin/vex-forms\.py "),
             "baseline": at(r"release-metadata\.py baseline "), "manifest": at(r"release-metadata\.py manifest "), "list": at(r"release-metadata\.py list "), "first": at(r"^cosign (login|sign)"), "attest": at(r"^cosign attest "), "lsign": at(r"cosign sign-blob .*release-files\.sha256\.bundle")}
    bad = ["release-sign.sh has no %s step" % k for k, v in marks.items() if v is None]
    if bad:
        return bad
    order = ["images", "cp", "vex", "baseline", "manifest", "list", "first", "attest", "lsign"]
    for a, b in zip(order, order[1:]):
        if not marks[a] < marks[b]:
            bad.append("the %s step must come before the %s step (the VEX and CSAF files are generated before the manifest and the list, and nothing is signed before them)" % (a, b))
    for k, need in (("images", ["--items witness-build/items.json", "--digests witness-build/digests.json", "--images-dir images"]),
                    ("vex", ["--openvex .vex/fosterstack-cache.openvex.json", "--images release-metadata/vex-images.json", '--version "$GITHUB_REF_NAME"']),
                    ("baseline", ["--admission witness-build/admission-baseline.json", '--tag "$GITHUB_REF_NAME"', '--commit "$GITHUB_SHA"']),
                    ("manifest", ["--items witness-build/items.json", "--vex-dir release-metadata", "--digests witness-build/digests.json", '--baseline-version "$baseline"'])):
        for n in need:
            if n not in lines[marks[k]]:
                bad.append("the %s step must carry %s" % (k, n))
    # REQ-CHAIN-007-AC8 (advisor ruling H, Oct 12): the release manifest stays an OCI referrer of each public digest (the v0.2.x attestation customers have):
    # one `cosign attest` per registry inside the loop over both digests, after every image signature, GHCR required and Docker Hub a loud, best-effort mirror
    atts = [l for l in lines if l.startswith("cosign attest ")]
    base = ('cosign attest --yes --signing-config .github/policy/cosign-signing-config.json --predicate release-metadata/release-manifest.json '
            '--type https://fosterstack.com/attestations/release-manifest/v1 ')
    want = {base + '"ghcr.io/$repo@$digest"', base + '"docker.io/$repo@$digest" || echo "::warning::could not attach the manifest referrer on docker.io/$repo@$digest: the GHCR referrer is authoritative"'}
    if sorted(atts) != sorted(want):
        bad.append("release-sign.sh must hold exactly these two `cosign attest` lines (the manifest as a release-manifest/v1 referrer of each public digest; GHCR required, "
                   "the Docker Hub mirror best-effort with a warning): %r" % atts)
    elif marks.get("attest") is not None:
        loop = next((i for i in range(marks["attest"], -1, -1) if lines[i].startswith("for digest in ")), None)
        if loop is None or lines[loop] != 'for digest in "$prod" "$fips"; do':
            bad.append('the manifest attestations must sit inside `for digest in "$prod" "$fips"; do` (both public digests)')
        last_img_sign = max((i for i, l in enumerate(lines) if re.match(r'cosign sign --yes ', l)), default=-1)
        if marks["attest"] < last_img_sign:
            bad.append("the manifest attestations must come after every image signature (nothing is attached to an unsigned image)")
    return bad


def removed(root):
    bad = [f"{f} still exists" for f in OLD if os.path.exists(os.path.join(root, f))]
    pp = os.path.join(root, ".github/workflows/stage-promote.yml")
    if os.path.exists(pp) and re.search(r"release-authori[sz]ation|authorize-acceptance-check", open(pp).read()):
        bad.append("stage-promote.yml still reads or writes a release-authorization predicate")
    rp = os.path.join(root, ".github/workflows/release.yml")
    if os.path.exists(rp) and "authorization" in (load(rp).get("jobs") or {}):
        bad.append("release.yml still has an authorization job")
    return bad


if __name__ == "__main__":
    cmd, a = sys.argv[1], sys.argv[2:]
    if cmd in ("stage", "credentials", "graph", "verify", "metadata") and not os.path.exists(a[0]):
        print("missing file: %s" % a[0]); sys.exit(1)
    fn = {"stage": lambda: stage(a[0]), "credentials": lambda: credentials(a[0]), "others": lambda: others(a[0]),
          "graph": lambda: graph(a[0]), "verify": lambda: verify(a[0]), "scan": lambda: scan(a[0], a[1]),
          "listed": lambda: listed(a[0], a[1]), "metadata": lambda: metadata(a[0]), "record": lambda: record(a[0], a[1:]), "removed": lambda: removed(a[0])}[cmd]
    bad = fn()
    print("; ".join(bad) or "ok")
    sys.exit(1 if bad else 0)
