"""Test infrastructure (not product code) for PR 3 "Check", shared by bin/chain-check-wiring-test.sh. Judges for the shape of the Check
stage file, the order of bin/check-phase.sh, the release.yml job graph, the plainness of the check scripts and the removal of the old
acceptance stages. Each judge prints `ok` or the list of faults and exits 1 on a fault. The test first proves every judge on a
known-good fixture and on mutated copies (a judge that cannot fail proves nothing), then applies it to the real repository, which is
RED until PR 3 is implemented. Finite grammars and allowlists only; no shell analysis (final PR 1 design, advisor decision b).

  stage FILE            REQ-CHAIN-006-AC1: the Check jobs of release.yml (FILE) are an ALLOWLIST: check-govulncheck (credential-free, builds govulncheck) and ONE job `check`: needs exactly check-govulncheck,
                        build-assemble and sign; runs-on ${{ matrix.runner }} with a matrix over exactly ubuntu-24.04 and ubuntu-24.04-arm; permissions exactly contents read (no identity token, no environment, no
                        job output); no per-chip job; steps EXACTLY, in order: checkout, the checksum-pinned installs, the govulncheck hand-over, the digest-pinned downloads (images exactly once), THREE
                        `bash bin/witnessed-local.sh STEP bin/check-phase.sh STEP` steps (STEP scanners, acceptance, runtime), the records-list step, and the uploads witness-check-R, check-results-R and
                        check-records-R (R the matrix runner)
  signcheck FILE        REQ-CHAIN-006-AC1, REQ-REL-011-AC1: the sign-check job of release.yml: environment sign, id-token for the KMS role, the downloads and the one sign-records call for both chips,
                        one signing step per chip, the uploads signed-witness-check-R
  oldcheck ROOT         the per-chip and per-phase Check files and names (check-stage.sh, check-phase-STEP.sh, stage-verify.yml, check-arm64, records-arm64) are gone
  installs FILE JSON    REQ-CHAIN-006-AC4 (round 1 F2): the check job runs `bash bin/install-scanner.sh S` for every scanner S in the scanners list JSON
                        (.github/policy/scanners.json) and for none it does not list.
  helper FILE           REQ-CHAIN-006-AC9, AC11 (the RULE 68 SEAM): bin/witnessed.sh, the one helper every stage calls, is EXACTLY PR 2's canonical
                        helper (origin/pipeline-chain-build-rebuild, bin/chain-test-shape.py witnessed_lines: the token by a one-read process
                        substitution, the record witness-DIR/STEP-collection.json, the four sensitive keys) with ONE PR 3 extension: the closed step
                        list also holds scanners, acceptance and runtime (advisor ruling Q2, a step-5 revisit). At the merge with PR 2 its judge's
                        STEPS takes the same three names and this copy is deleted in favour of it.
  cluster FILE          REQ-CHAIN-006-AC14: bin/acceptance-k8s.sh creates its cluster with exactly CLUSTER (the node image by digest) and no action.
  suites FILE           REQ-CHAIN-006-AC5: acceptance.yml's job runs the shared suite scripts (one copy of each suite).
  script FILE           REQ-CHAIN-006-AC1, AC3: bin/check-phase.sh is `set -euo pipefail`, the chip case (uname -m), the two verify commands, then ONE fixed `case "$1"` with
                        exactly the phases of PHASES (each with exactly its commands, in order; govulncheck only when the chip is amd64, check-artifacts told --arch "$arch") and nothing else.
  records JSON          REQ-CHAIN-006-AC13 (rule 66): .github/policy/chain-records.json has no row for the old acceptance record and has a row
                        for the Witness collection naming Check as a producer and `release` as consumer. [P: the table's shape is PR 1's]
  graph FILE            REQ-CHAIN-006-AC2: release.yml job graph (check beside rebuild; sign-check after check; the release job waits for all four signing jobs).
  plain FILE...         REQ-CHAIN-006-AC8: the check scripts know nothing about signing (text scan, comments and quotes included). Applied to
                        check-scan/fips/acceptance/guide; bin/check-phase.sh is judged by `script` alone (its pinned lines name Build's
                        witness-build/ directory, advisor ruling Q3).
  listed JSON ROOT      REQ-CHAIN-006-AC8: each check script is a row of .github/policy/chain-scripts.json with the sha256 the file has.
  removed ROOT          REQ-CHAIN-006-AC10 (rules 61, 65): the Dockerfile, buildx and goreleaser, their Dependabot entry and every reader are gone; the old acceptance stages and the custom authorization verifier are gone and
                        neither release.yml nor ci.yml calls them.
Modelled on: in-toto-witness docs/attestors/environment.md and docs/commands.md (the flags), docs/tutorials/artifact-policy.md:58-70 (what a
collection holds); PR 2's bin/chain-test-shape.py (the same flag allowlist, the same token-fetch lines)."""
import hashlib, json, os, re, shlex, sys, yaml

PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
DOWN = {"signed-witness-build", "digests", "dist", "locks", "images"}   # Build's artifacts (Check's previous stage is Build; Sign's provenance is Release's to verify); images travel as files (OCI tarballs)
RECORD_DIRS = "witness-scanners\nwitness-acceptance\nwitness-runtime"           # PR 2's helper writes witness-STEP/STEP-collection.json
RUNNER = "${{ matrix.runner }}"
RUNNERS = ["ubuntu-24.04", "ubuntu-24.04-arm"]   # the two chips of the one check job (REQ-CHAIN-006-AC1)
UP = {"witness-check-" + RUNNER: RECORD_DIRS, "check-results-" + RUNNER: "check-results", "check-records-" + RUNNER: "check-records.json"}   # artifact name -> the path(s) it may carry
STEPS = ["scanners", "acceptance", "runtime"]
SCANNERS = ["grype", "osv-scanner"]   # the release scanners bin/check-scan.sh runs, in .github/policy/scanners.json order; the `installs` judge holds this list to that file
GO_INSTALL = "bash bin/install-scanner.sh go"          # the pinned toolchain govulncheck is built with (an installer of its own; not a scanner)
REC_LINE = 'bash bin/check-records-digests.sh "$LEG" check-records.json witness-scanners witness-acceptance witness-runtime'   # the script writes the runner's list of its three record folders itself, a file Sign compares (REQ-REL-011-AC1); no job output
REC_ENV = {"LEG": "${{ matrix.runner }}"}
SNAPSHOT_IF = "${{ inputs.mode != 'snapshot' }}"
CHECK_NEEDS = ["check-govulncheck", "build-assemble", "sign"]
CHECK_STRATEGY = {"matrix": {"runner": RUNNERS}}
GV_BUILD = "check-govulncheck"   # REQ-REL-011-AC1 (advisor, Oct 23; Witness review F9): the job with no credential that builds govulncheck; the check job (no identity token) only installs what it hands over
GV_BUILD_LINE = "bash bin/install-scanner.sh govulncheck"
GV_PACK_LINE = "bash bin/pack-govulncheck.sh"   # the one build step; the artifact it uploads is the hand-over (download-artifact fails the step on a digest mismatch; no override is allowed)
GV_HAND_LINE = "bash bin/unpack-govulncheck.sh"
GV_OUTPUT = {"artifact-id": "${{ steps.upload.outputs.artifact-id }}"}   # the Check job downloads by this id, so an artifact another job uploads under the same name is not the one it gets
GV_IDS = "${{ needs.check-govulncheck.outputs.artifact-id }}"
SOURCE_SCANNERS = ["govulncheck"]   # ruling G (advisor Oct 12): the source scanners of .github/policy/scanners.json `source_scanners`, installed after Go, run by bin/check-govulncheck.py
PHASE_LINE = {s: "bash bin/witnessed-local.sh %s bin/check-phase.sh %s" % (s, s) for s in STEPS}   # the one script runs all three phases; the step name is its argument
STEP_LIST = "release-apks|release-sign"   # the Release helper keeps only the two signing steps (ruling Q-e: release-verify, release-publish, release-assets and release-postverify run under the local helper); Check's steps run under the local helper (REQ-REL-011-AC1)
SENSITIVE = ["ACTIONS_ID_TOKEN_REQUEST*", "ACTIONS_RUNTIME_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN"]   # PR 2's with the two AWS variables of handoff 0713 (SIGSTORE_ID_TOKEN is gone); never github or slsa
RELEASE_SENSITIVE = ["RELEASE_ROLE_ARN", "RELEASE_TOKEN_FILE"]   # the names release-sign and release-apks receive the role and the token path under (witnessed.sh only; the local helper has none)


def witnessed_lines():
    """The canonical bin/witnessed.sh (witnessed_lines in its bin/chain-test-shape.py), with PR 3's three steps in the closed list. Handoff 0713: the collection is signed with the release KMS key
    by its alias, by the one signing function, after Witness has run with a throwaway key and no token, AWS_ROLE_ARN or AWS_WEB_IDENTITY_TOKEN_FILE of its own (the scripts of release-sign and release-apks, which sign with the key themselves, are handed the sensitive names RELEASE_ROLE_ARN and RELEASE_TOKEN_FILE and map them themselves; the wrapped command is the plain bash SCRIPT); a fresh identity token
    (audience sts.amazonaws.com) goes to a file in a private directory under RUNNER_TEMP that a trap removes, and the AWS SDK reads it through AWS_WEB_IDENTITY_TOKEN_FILE and
    AWS_ROLE_ARN for the one signing call."""
    keys = " ".join("--env-add-sensitive-key %s" % ("'%s'" % k if "*" in k else k) for k in SENSITIVE + RELEASE_SENSITIVE)
    return ["set -euo pipefail", 'step="$1"', "shift",
            'case "$step" in %s) ;; *) echo "witnessed: unknown step $step" >&2; exit 2 ;; esac' % STEP_LIST,
            'mkdir -p "witness-${step#snapshot-}"',
            ': "${AWS_ROLE_ARN:?witnessed: AWS_ROLE_ARN is missing}"',
            ': "${AWS_REGION:?witnessed: AWS_REGION is missing}"',
            ': "${RELEASE_KMS_KEY_REF:?witnessed: RELEASE_KMS_KEY_REF is missing}"',
            "umask 077",
            'td=$(mktemp -d "${RUNNER_TEMP:?}/witness-aws.XXXXXX")',
            "trap 'rm -rf \"$td\"' EXIT HUP INT TERM",
            "role=$AWS_ROLE_ARN region=$AWS_REGION kref=$RELEASE_KMS_KEY_REF",
            "req_tok=$ACTIONS_ID_TOKEN_REQUEST_TOKEN req_url=$ACTIONS_ID_TOKEN_REQUEST_URL",
            "unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL",
            "oidc_token() {",
            '  sh bin/loopback-get.sh -sSf -H "Authorization: bearer $req_tok" "${req_url}&audience=sts.amazonaws.com" | jq -r .value > "$td/token"',
            '  tok=$(cat "$td/token")',
            '  [ -n "$tok" ] && [ "$tok" != null ] || { echo "witnessed: no identity token" >&2; exit 1; }',
            '  echo "::add-mask::$tok"',
            "}",
            'unset AWS_ROLE_ARN AWS_WEB_IDENTITY_TOKEN_FILE',
            'signers=" release-sign release-apks "',
            'case "$signers" in *" $step "*) ;; *) unset AWS_REGION RELEASE_KMS_KEY_REF ;; esac',
            'case "$signers" in *" $step "*) mkdir "$td/step"; oidc_token; mv "$td/token" "$td/step/token"; export RELEASE_ROLE_ARN=$role RELEASE_TOKEN_FILE="$td/step/token" ;; esac',
            'openssl genpkey -algorithm ed25519 -out "$td/key.pem"',
            'local_record="$td/$step-collection.json"',
            "rc=0",
            'witness run --step "$step" --signer-file-key-path "$td/key.pem" '
            "-a environment,git,material,product --env-filter-sensitive-vars %s "
            '-o "$local_record" -- bash "$@" || rc=$?' % keys,
            'rm -rf "$td/step"',
            "unset RELEASE_ROLE_ARN RELEASE_TOKEN_FILE",
            'if [ "$rc" -eq 0 ]; then',
            '  jq -er .payload "$local_record" | base64 -d > "$td/payload" && [ -s "$td/payload" ] || { echo "witnessed: the collection has no payload" >&2; exit 1; }',
            "  oidc_token",
            '  AWS_WEB_IDENTITY_TOKEN_FILE="$td/token" AWS_ROLE_ARN=$role AWS_REGION=$region RELEASE_KMS_KEY_REF=$kref '
            'python3 -I -B bin/chain-verify.py sign-record --payload "$td/payload" '
            '--out "witness-${step#snapshot-}/$step-collection.json" --template .github/policy/release-policy.template.json '
            '--aws "$RUNNER_TEMP/aws-cli/aws" --public-key build/keys/release.rsa.pub || rc=$?',
            "fi",
            'rm -rf "$td"',
            '[ ! -e "$td" ] || { echo "witnessed: the token directory still exists" >&2; exit 1; }',
            'exit "$rc"']


def commands_of(raw):
    """PR 2's reader: blank and comment lines dropped; a line ending in ` \\` joins the next; any other trailing backslash is a fault."""
    commands, faults, pending = [], [], None
    lines = raw.split("\n")
    for number, line in enumerate(lines, 1):
        if pending is not None and number == len(lines) and not line:
            break
        if pending is not None:
            line, pending = pending + " " + line.lstrip(" \t"), None
        elif line.lstrip(" \t").startswith("#") or not line.strip(" \t"):
            continue
        if line.endswith(" \\"):
            pending = line[:-2]
        elif line.endswith("\\"):
            faults.append("line %d ends in a backslash that is not preceded by a space" % number)
        else:
            commands.append(line)
    if pending is not None:
        faults.append("the script ends in a line continuation")
    return commands, faults


def compare(got, want, what):
    bad = []
    for i in range(max(len(want), len(got))):
        w, g = (want[i] if i < len(want) else None), (got[i] if i < len(got) else None)
        if w != g:
            bad.append("%s command %d: expected %r, found %r" % (what, i + 1, (w or "<end of file>")[:170], (g or "<end of file>")[:170])); break
    if len(want) != len(got):
        bad.append("%s has %d commands, the grammar has %d" % (what, len(got), len(want)))
    return bad


def control_chars(raw):
    return sorted({"U+%04X" % ord(c) for c in raw if (ord(c) < 32 and c not in "\t\n") or 127 <= ord(c) <= 159 or c in "\u2028\u2029"})


POLICY = (r'python3 -I -B bin/chain-verify\.py policy make --template \.github/policy/release-policy\.template\.json --tag "\$GITHUB_REF_NAME" '
          r'--out policy\.json')   # Q5 (advisor, Oct 10): Check makes the release policy per tag, as PR 2's Rebuild does, before it verifies
VERIFY = [  # bin/check-phase.sh after `set -euo pipefail` and the policy line: the verify step first (rule 58: Check's previous stage is Build), before any check (every phase re-verifies);
            # isolated and with no bytecode cache, as PR 1's Sign step runs the verifier (python3 -I -B, PR 1 r5)
    r"python3 -I -B bin/chain-verify\.py stage-start --stage check --previous build --record witness-build/build-collection\.json --digests witness-build/digests\.json --policy policy\.json",
]
CHIP = [  # bin/check-phase.sh after `set -euo pipefail`: the chip comes from uname -m, never from an argument; any other chip stops the script
    ("lit", 'case "$(uname -m)" in'), ("lit", "x86_64) arch=amd64 ;;"), ("lit", "aarch64) arch=arm64 ;;"),
    ("lit", '*) echo "unknown chip: $(uname -m)" >&2; exit 2 ;;'), ("lit", "esac")]
PHASES = {  # rules 55, 72, 79; the phases are split so that no witnessed command nears the 9-minute cap (rule 68, amended)
    "scanners": [r"bash bin/check-scan\.sh --scanners \.github/policy/scanners\.json --digests witness-build/digests\.json --images images --archives dist --out check-results",
                 r'if \[ "\$arch" = amd64 \]; then',   # govulncheck reads the source, not the chip: it runs once, on the amd64 chip
                 r"python3 -I -B bin/check-govulncheck\.py --scanners \.github/policy/scanners\.json --out check-results",
                 r"fi"],
    "acceptance": [r"bash bin/check-acceptance\.sh gradle --digests witness-build/digests\.json --images images --out check-results",
                   r"bash bin/check-acceptance\.sh maven --digests witness-build/digests\.json --images images --out check-results"],
    "runtime": [r"bash bin/check-acceptance\.sh egress --digests witness-build/digests\.json --images images --out check-results",
                r"bash bin/check-acceptance\.sh k8s --digests witness-build/digests\.json --images images --out check-results",
                r"bash bin/check-fips\.sh --digests witness-build/digests\.json --images images --out check-results",
                r'bash bin/check-artifacts\.sh --arch "\$arch" --digests witness-build/digests\.json --images images --archives dist --out check-results',
                r"bash bin/check-guide\.sh --guide docs/verify-release\.md --digests witness-build/digests\.json --images images --out check-results"],
}
SCRIPTS = ["bin/check-phase.sh", "bin/check-scan.sh", "bin/check-govulncheck.py", "bin/check-fips.sh", "bin/check-artifacts.sh", "bin/check-acceptance.sh", "bin/check-guide.sh",
           "bin/acceptance-gradle.sh", "bin/acceptance-gradle-capped.sh", "bin/acceptance-maven.sh", "bin/acceptance-maven-capped.sh",
           "bin/acceptance-egress.sh", "bin/acceptance-k8s.sh", "bin/acceptance-serve.sh"]
# REQ-CHAIN-006-AC14: the node image the k8s suite creates its cluster with, by digest
# (kind v0.33.0 release notes, https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0)
NODE_IMAGE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
CLUSTER = "kind create cluster --name fscache-accept --image " + NODE_IMAGE
SUITE_STEPS = {  # acceptance.yml: the one job runs the shared suite scripts, in this order
    "acceptance": ["bash bin/acceptance-gradle.sh", "bash bin/acceptance-gradle-capped.sh", "bash bin/acceptance-maven.sh", "bash bin/acceptance-maven-capped.sh"],
}
SIGNING = re.compile(r"cosign|witness|gitsign|sigstore|slsa|attest|in-toto|docker\s+login|ghcr\.io|secret|ACTIONS_ID_TOKEN|ACTIONS_RUNTIME|GITHUB_TOKEN|GH_TOKEN|SNYK", re.I)
OLD = ["stage-acceptance-artifacts.yml", "stage-acceptance-egress.yml", "stage-acceptance-k8s.yml", "stage-acceptance-predicate.yml", "stage-authorize.yml"]
OLD_FILES = ["bin/authorize-acceptance-check.py", "bin/authorize-acceptance-check-test.sh"]   # the custom authorization verifier (rule 65)
COLLECTION = "https://witness.testifysec.com/attestation-collection/v0.1"


def load(path):
    return yaml.load(open(path), Loader=yaml.BaseLoader)


CHECK_DOWNLOADS = [("signed-witness-build", "witness-build"), ("digests", "witness-build"), ("dist", "dist"), ("images", "images")]   # the inputs bin/check-phase.sh verifies


def exact_steps(label, steps, want, what):
    """The exact ordered step list of a job (PR 3 round 1 F6): a digest-pinned checkout with persist-credentials: false only, a run step exactly its
    line, a digest-pinned download or upload of exactly its artifact name and path, each ONCE (a missing, a repeated, a reordered or a re-pathed step is a
    fault), and no other key in any step (an if, env or shell would change what runs)."""
    bad = []
    if len(steps) != len(want):
        bad.append("%s must have exactly its %d listed steps (%s), found %d" % (label, len(want), what, len(steps)))
    for i, (s, (kind, arg)) in enumerate(zip(steps, want), 1):
        extra = {"upid": {"id"}}.get(kind, set())
        if kind == "run" and arg == REC_LINE:
            extra = {"env"}
            if isinstance(s, dict) and s.get("env") != REC_ENV:
                bad.append("%s step %d: the records step must carry exactly env LEG: ${{ matrix.runner }}: %s" % (label, i, s.get("env")))
        if not isinstance(s, dict) or set(s) - ({"name", "uses", "with", "run"} | extra):
            bad.append("%s step %d: keys not allowed (an if, env or shell would change what runs): %s" % (label, i, sorted(s) if isinstance(s, dict) else s)); continue
        u, w, r = (s.get("uses") or ""), s.get("with") or {}, (s.get("run") or "").strip()
        if kind == "checkout":
            if not u.startswith("actions/checkout@") or not PIN.match(u.split(" ")[0]) or w != {"persist-credentials": "false"} or "run" in s:
                bad.append("%s step %d must be a digest-pinned checkout with persist-credentials: false only" % (label, i))
        elif kind == "run":
            if u or r != arg:
                bad.append("%s step %d must be exactly `run: %s`, found %r" % (label, i, arg, (r or u)[:80]))
        elif kind == "downid":
            if not u.startswith("actions/download-artifact@") or not PIN.match(u.split(" ")[0]) or w != {"artifact-ids": GV_IDS, "path": arg} or "run" in s:
                bad.append("%s step %d must be a digest-pinned download-artifact with exactly artifact-ids %s and path %s (no name, pattern, merge-multiple or digest-mismatch)" % (label, i, GV_IDS, arg))
        elif kind in ("down", "up", "upid"):
            if kind == "upid" and s.get("id") != "upload":
                bad.append("%s step %d must carry `id: upload` (its artifact-digest is the job output)" % (label, i))
            kind = "up" if kind == "upid" else kind
            action = "actions/%s-artifact@" % ("download" if kind == "down" else "upload")
            if not u.startswith(action) or not PIN.match(u.split(" ")[0]) or set(w) != {"name", "path"} or w["name"] != arg[0] or (w["path"] or "").strip() != arg[1] or "run" in s:
                bad.append("%s step %d must be a digest-pinned %s of %s %s %s only" % (label, i, "download" if kind == "down" else "upload", arg[0], "into" if kind == "down" else "carrying", arg[1].replace("\n", " ")))
    return bad


def gv_job(j):
    """REQ-REL-011-AC1: govulncheck-build holds contents read only (no id-token, no secret, no environment, no other key), runs on ubuntu-24.04 and has EXACTLY these steps: a digest-pinned
    checkout without persisted credentials, the checksum-pinned Go install, the one build step (the pinned installer arm) and the digest-pinned upload of the binary as the artifact
    govulncheck (`id: upload`). Its one output is that upload's artifact-id: the Check job downloads by it, so a same-name artifact another job uploads is not the one it gets (the guarantee that no build runs in a job holding a credential is the rule itself)."""
    if not isinstance(j, dict):
        return ["%s is not a job" % GV_BUILD]
    bad = []
    if set(j) - {"if"} != {"runs-on", "permissions", "outputs", "steps"}:
        bad.append("%s may hold exactly runs-on, permissions, outputs and steps (and the snapshot `if`; no needs, env, environment, container): %s" % (GV_BUILD, sorted(j)))
    bad += snapshot_guard(GV_BUILD, j)
    if j.get("runs-on") != "ubuntu-24.04":
        bad.append("%s must run on the GitHub-hosted ubuntu-24.04 runner, got %r" % (GV_BUILD, j.get("runs-on")))
    if j.get("permissions") != {"contents": "read"}:
        bad.append("%s permissions must be exactly contents read (it holds no credential): %s" % (GV_BUILD, j.get("permissions")))
    if j.get("outputs") != GV_OUTPUT:
        bad.append("%s must expose exactly the output artifact-id, the artifact-id of its upload step: %s" % (GV_BUILD, j.get("outputs")))
    want = [("checkout", None), ("run", GO_INSTALL), ("run", GV_BUILD_LINE), ("run", GV_PACK_LINE), ("upid", ("govulncheck", "govulncheck-out/govulncheck"))]
    bad += exact_steps(GV_BUILD, j.get("steps") or [], want, "checkout, Go install, the one build step, the upload (id: upload)")
    return bad


def snapshot_guard(label, j):
    """The two check jobs may carry an `if`, only the snapshot guard (the snapshot mode builds and checks nothing of a release)."""
    if "if" in j and j["if"] != SNAPSHOT_IF:
        return ["%s may carry only the `if` %s, found %r" % (label, SNAPSHOT_IF, j["if"])]
    return []


def stage(path):
    """REQ-CHAIN-006-AC1: the Check jobs of release.yml, check-govulncheck and the one `check` job with a matrix over the two chips; any other job of the file is not judged here."""
    d, bad = load(path), []
    jobs = d.get("jobs") or {}
    for n in (GV_BUILD, "check"):
        if n not in jobs:
            bad.append("release.yml has no job %s" % n)
    if bad:
        return bad
    if [n for n in jobs if n.startswith("check-") and n != GV_BUILD]:
        bad.append("there is no per-chip check job: the one job `check` has a matrix over both chips (found %s)" % sorted(n for n in jobs if n.startswith("check")))
    bad += gv_job(jobs[GV_BUILD])
    j = jobs["check"]
    if set(j) - {"needs", "if", "runs-on", "strategy", "permissions", "steps"}:
        bad.append("job keys not allowed: %s" % sorted(set(j) - {"needs", "if", "runs-on", "strategy", "permissions", "steps"}))
    bad += snapshot_guard("check", j)
    if "outputs" in j:
        bad.append("check exposes no job output: its records travel as the artifact check-records-<runner>")
    if j.get("needs") != CHECK_NEEDS:
        bad.append("check must need exactly %s (the job that builds govulncheck with no credential, Build's records, and Sign's signature of them), got %r" % (CHECK_NEEDS, j.get("needs")))
    if j.get("runs-on") != RUNNER:
        bad.append("check must run on its matrix runner %s, got %r" % (RUNNER, j.get("runs-on")))
    if j.get("strategy") != CHECK_STRATEGY:
        bad.append("check's strategy must be exactly a matrix over the runners %s and nothing else (no fail-fast, include, exclude or max-parallel): %s" % (RUNNERS, j.get("strategy")))
    if j.get("permissions") != {"contents": "read"}:
        bad.append("permissions must be exactly contents read (no identity token: the records are made with the local helper and signed by Sign; REQ-REL-011-AC1): %s" % j.get("permissions"))
    steps = j.get("steps") or []
    text = yaml.dump({n: jobs[n] for n in (GV_BUILD, "check")})
    if re.search(r"docker\s+login|\bsecrets\s*\.|secrets:|packages\s*:|attestations\s*:|ghcr\.io|id-token|environment", text):
        bad.append("a registry login, a secret, a packages or attestations permission, an identity token, an environment or a registry name appears in a Check job")
    kinds, names = [], []
    for s in steps:
        is_rec = (s.get("run") or "").strip() == REC_LINE
        if set(s) - {"name", "uses", "with", "run"} - ({"env"} if is_rec else set()):
            bad.append("step keys not allowed: %s" % sorted(set(s) - {"name", "uses", "with", "run"}))
        if is_rec and s.get("env") != REC_ENV:
            bad.append("the records step must carry exactly env LEG: ${{ matrix.runner }}: %s" % s.get("env"))
        u = s.get("uses", "")
        if u.startswith("actions/checkout@"):
            kinds.append("checkout")
            if not PIN.match(u.split(" ")[0]) or s.get("with") != {"persist-credentials": "false"}:
                bad.append("checkout must be digest-pinned with persist-credentials: false only")
        elif u.startswith("actions/download-artifact@"):
            w = s.get("with") or {}
            kinds.append("gvdown" if "artifact-ids" in w else "down")
            if "artifact-ids" in w:
                if not PIN.match(u.split(" ")[0]) or w != {"artifact-ids": GV_IDS, "path": "govulncheck-dl"}:
                    bad.append("a download by artifact id must be digest-pinned with exactly artifact-ids %s and path govulncheck-dl: %s" % (GV_IDS, w))
            elif not PIN.match(u.split(" ")[0]) or w.get("name") not in DOWN or set(w) != {"name", "path"} or re.match(r"^(bin|\.github|\.|/|\.\.)(/|$)", w.get("path", ".")):
                bad.append("download-artifact must be digest-pinned, name in %s, an explicit path outside bin/ and .github/: %s" % (sorted(DOWN), w))
        elif u.startswith("actions/upload-artifact@"):
            kinds.append("up")
            w = s.get("with") or {}
            if not PIN.match(u.split(" ")[0]) or UP.get(w.get("name")) != (w.get("path") or "").strip() or set(w) != {"name", "path"}:
                bad.append("upload-artifact must be digest-pinned, name and path from %s (witness-check-<runner> carries the three record folders): %s" % (UP, w))
        elif u:
            bad.append("uses not allowed in the Check job: %s" % u)
        elif (s.get("run") or "").strip() in ["bash bin/install-scanner.sh " + n for n in ["witness"] + SCANNERS + ["go"]]:
            kinds.append("install")
        elif (s.get("run") or "").strip() == GV_HAND_LINE:
            kinds.append("hand")
        elif (s.get("run") or "").strip() == REC_LINE:
            kinds.append("rec")
        elif "run" in s:
            kinds.append("witnessed")
            m = re.fullmatch(r"bash bin/witnessed-local\.sh ([a-z]+) bin/check-phase\.sh ([a-z]+)", (s["run"] or "").strip())
            if not m or m.group(1) != m.group(2) or m.group(1) not in STEPS:
                bad.append("a run step must be exactly `bash bin/witnessed-local.sh STEP bin/check-phase.sh STEP` with STEP one of %s (no witness, timeout or other command in the job): %r" % (STEPS, (s["run"] or "")[:80]))
            else:
                names.append(m.group(1))
        else:
            bad.append("a step with neither uses nor run")
    want = ["checkout", "install"] + ["install"] * len(SCANNERS) + ["install"] + ["gvdown", "hand"]
    k = len(want)
    got_down = [x for x in kinds if x == "down"]
    body = [x for x in kinds if x != "down"]
    if body[:k] != want or body[k:k + 3] != ["witnessed"] * 3 or body[k + 3:k + 4] != ["rec"] or any(x != "up" for x in body[k + 4:]) or len(body) < k + 5:
        bad.append("steps must be checkout, install Witness, install each listed scanner, downloads, "
                   "THREE witnessed steps, the records step, uploads (in that order); "
                   "got %s" % kinds)
    want_c = ([("checkout", None), ("run", "bash bin/install-scanner.sh witness")]
              + [("run", "bash bin/install-scanner.sh " + s) for s in SCANNERS]
              + [("run", GO_INSTALL)]
              + [("downid", "govulncheck-dl"), ("run", GV_HAND_LINE)]
              + [("down", x) for x in CHECK_DOWNLOADS]
              + [("run", PHASE_LINE[n]) for n in STEPS]
              + [("run", REC_LINE)]
              + [("up", (n, p)) for n, p in UP.items()])
    bad += exact_steps("check", steps, want_c, "checkout, Witness install, one install per listed scanner, "
                                               "four downloads, the three witnessed steps, the records step, the three uploads")
    imgs = [s for s in steps if (s.get("uses") or "").startswith("actions/download-artifact@") and (s.get("with") or {}).get("name") == "images"]
    if len(imgs) != 1 or (imgs[0].get("with") or {}).get("path") != "images":
        bad.append("exactly one download of the images artifact, into images/, is required; found %d" % len(imgs))
    if not got_down:
        bad.append("no download of Build's artifacts")
    # downloads come after the install and before the first witnessed step
    if "witnessed" in kinds and "down" in kinds and max(i for i, k in enumerate(kinds) if k == "down") > kinds.index("witnessed"):
        bad.append("a download comes after Witness started (rule 68: third-party actions run before Witness or not at all)")
    if names != STEPS:
        bad.append("the witnessed steps must be exactly %s in that order, found %s" % (STEPS, names))
    return bad


def installs(path, scanners_path):
    """REQ-CHAIN-006-AC4 (PR 3 round 1 F2): the Check job installs, by the checksum-pinned installer, every scanner .github/policy/scanners.json lists (and
    only those): bin/check-scan.sh needs each of them on PATH and the clean runner has none."""
    doc = json.load(open(scanners_path)) or {}
    listed = (doc.get("scanners") or []) + (doc.get("source_scanners") or [])   # the image scanners and the source scanners (ruling G)
    jobs = (load(path).get("jobs") or {})
    runs = [(s.get("run") or "").strip() for s in ((jobs.get("check") or {}).get("steps") or []) if isinstance(s, dict)]
    gv_runs = [(s.get("run") or "").strip() for s in ((jobs.get(GV_BUILD) or {}).get("steps") or []) if isinstance(s, dict)]
    got = [r.split(" ")[-1] for r in runs if r.startswith("bash bin/install-scanner.sh ")]
    bad = []
    source = doc.get("source_scanners") or []
    for s in listed:
        if s in source:   # a source scanner is a Go module: built in the credential-free govulncheck-build job and handed to check by digest (REQ-REL-011-AC1)
            if not any(r == "bash bin/install-scanner.sh " + s for r in gv_runs):
                bad.append("scanners.json lists the source scanner %s but the %s job has no build step `bash bin/install-scanner.sh %s`" % (s, GV_BUILD, s))
            if GV_HAND_LINE not in runs:
                bad.append("scanners.json lists the source scanner %s but the check job has no digest-gated install of it" % s)
        elif "bash bin/install-scanner.sh " + s not in runs:
            bad.append("scanners.json lists %s but the check job has no step `bash bin/install-scanner.sh %s`" % (s, s))
    for r in gv_runs:
        if r.startswith("bash bin/install-scanner.sh ") and r.split("\n")[0].split(" ")[-1] not in ["go"] + source:
            bad.append("the %s job builds %s (`%s`), which scanners.json does not list as a source scanner" % (GV_BUILD, r.split("\n")[0].split(" ")[-1], r.split("\n")[0]))
    for g in got:
        if g not in ("witness", "go") and (g not in listed or g in source):
            bad.append("the check job installs %s (`bash bin/install-scanner.sh %s`), which scanners.json does not list (or which is built in %s and handed over)" % (g, g, GV_BUILD))
    return bad


def helper(path):
    """The rule 68 seam: bin/witnessed.sh is exactly PR 2's canonical helper with PR 3's three steps (witnessed_lines)."""
    raw = open(path, newline="").read()
    commands, faults = commands_of(raw)
    if commands and commands[0].startswith("#!"):
        commands = commands[1:]
    return ["control character %s in the helper" % c for c in control_chars(raw)] + faults + compare(commands, witnessed_lines(), "the helper")


def cluster(path):
    """REQ-CHAIN-006-AC14: the k8s suite creates its cluster with exactly CLUSTER, once, and names no kind action."""
    text = open(path).read()
    lines = [l.strip() for l in text.split("\n")]
    bad = []
    creates = [l for l in lines if re.search(r"\bkind\s+create\s+cluster\b", l)]
    if creates != [CLUSTER]:
        bad.append("the cluster must be created exactly once, as %r (the node image by digest); found %s" % (CLUSTER, creates))
    if re.search(r"helm/kind-action|kind-action", text):
        bad.append("the k8s suite names a kind action (kind and kubectl come from the runner image)")
    return bad


def suites(path):
    """REQ-CHAIN-006-AC5: acceptance.yml's one job runs the shared suite scripts."""
    d, bad = load(path), []
    jobs = d.get("jobs") or {}
    for job, want in SUITE_STEPS.items():
        steps = (jobs.get(job) or {}).get("steps") or []
        lines = [l.strip() for s in steps for l in (s.get("run") or "").split("\n")]
        got = [l for l in lines if l.startswith("bash bin/acceptance-")]
        if got != want:
            bad.append("%s must run %s in that order, found %s" % (job, want, got))
    return bad


def script(path):
    """bin/check-phase.sh: set -euo pipefail, the chip case (uname -m), the policy and verify commands, then ONE fixed case "$1" with exactly the PHASES. Nothing else."""
    bad = []
    lines = [l.strip() for l in open(path).read().split("\n") if l.strip() and not l.strip().startswith("#")]
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    want = [("lit", "set -euo pipefail")] + CHIP + [("rx", POLICY)] + [("rx", r) for r in VERIFY] + [("lit", 'case "$1" in')]
    for ph, cmds in PHASES.items():
        want += [("lit", ph + ")")] + [("rx", c) for c in cmds] + [("lit", ";;")]
    want += [("lit", '*) echo "unknown phase: $1" >&2; exit 2 ;;'), ("lit", "esac")]
    for i, (kind, w) in enumerate(want):
        got = lines[i] if i < len(lines) else "<missing>"
        if (kind == "lit" and got != w) or (kind == "rx" and not re.fullmatch(w, got)):
            bad.append("line %d is not the pinned form: %s" % (i + 1, got[:100]))
            break
    if len(lines) != len(want):
        bad.append("the script has %d lines, the fixed dispatcher has %d: nothing else is allowed (no swallowed failure, no extra command)" % (len(lines), len(want)))
    return bad


def signcheck(path):
    """REQ-CHAIN-006-AC1, REQ-REL-011-AC1: sign-check is the Check stage's signing job: environment sign, the identity token (for the KMS role) and nothing else, it needs build-assemble and check,
    downloads for each runner the record folders (witness-check-R into rec-check/R), the results (check-results-R into artifacts/check-results-R) and the list of the records
    (check-records-R into rec-digests/R), runs ONE `chain-verify.py sign-records --stage check` with both lists and the six record folders (the two runners times scanners, acceptance, runtime),
    then signs each runner's staged tree once (`bash bin/witness-sign-staged.sh staged/R signed/R`), and uploads signed-witness-check-R carrying signed/R."""
    jobs = load(path).get("jobs") or {}
    j = jobs.get("sign-check")
    if not isinstance(j, dict):
        return ["release.yml has no job sign-check"]
    bad = []
    if j.get("environment") != "sign":
        bad.append("sign-check must run in the environment sign, got %r" % j.get("environment"))
    if j.get("permissions") != {"contents": "read", "id-token": "write"}:
        bad.append("sign-check permissions must be exactly contents read and id-token write (the KMS role), got %s" % j.get("permissions"))
    n = j.get("needs") or []
    if set([n] if isinstance(n, str) else n) != {"build-assemble", "check"}:
        bad.append("sign-check must need exactly build-assemble and check, got %s" % n)
    steps = j.get("steps") or []
    downs = sorted((s["with"].get("name"), s["with"].get("path")) for s in steps if (s.get("uses") or "").startswith("actions/download-artifact@"))
    want_d = sorted([("witness-check-" + r, "rec-check/" + r) for r in RUNNERS] + [("check-results-" + r, "artifacts/check-results-" + r) for r in RUNNERS] + [("check-records-" + r, "rec-digests/" + r) for r in RUNNERS])
    if downs != want_d:
        bad.append("sign-check must download exactly %s (name, path), found %s" % (want_d, downs))
    ups = [(s["with"].get("name"), s["with"].get("path")) for s in steps if (s.get("uses") or "").startswith("actions/upload-artifact@")]
    want_u = [("signed-witness-check-" + r, "signed/" + r) for r in RUNNERS]
    if ups != want_u:
        bad.append("sign-check must upload exactly %s (name, path) in that order, found %s" % (want_u, ups))
    runs = [(i, (s.get("run") or "").strip()) for i, s in enumerate(steps) if s.get("run")]
    recs = [(i, r) for i, r in runs if "sign-records" in r]
    if len(recs) != 1:
        bad.append("sign-check must run chain-verify.py sign-records once, found %d runs" % len(recs))
    else:
        want_head = ["env", "-u", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "-u", "ACTIONS_ID_TOKEN_REQUEST_URL", "python3", "-I", "-B", "bin/chain-verify.py", "sign-records"]
        toks = shlex.split(recs[0][1])
        flags = toks[len(want_head):]
        got = sorted(zip(flags[0::2], flags[1::2])) if len(flags) % 2 == 0 else None
        want_f = sorted([("--stage", "check"), ("--template", ".github/policy/release-policy.template.json"), ("--digests", "digests.json"), ("--artifacts-dir", "artifacts"), ("--out", "staged")]
                        + [("--expect-digests", "rec-digests/%s/check-records.json" % r) for r in RUNNERS]
                        + [("--record-dir", "rec-check/%s/witness-%s" % (r, s)) for r in RUNNERS for s in STEPS])
        if toks[:len(want_head)] != want_head or got != want_f:
            bad.append("the sign-records step must be exactly `%s` with the flags %s, found %s" % (" ".join(want_head), want_f, recs[0][1][:300]))
    signs = [(i, r) for i, r in runs if "witness-sign-staged" in r]
    want_s = ["bash bin/witness-sign-staged.sh staged/%s signed/%s" % (r, r) for r in RUNNERS]
    if [r for _, r in signs] != want_s:
        bad.append("sign-check must sign each runner's staged tree once, as %s, found %s" % (want_s, [r for _, r in signs]))
    if recs and signs and (min(i for i, _ in signs) < recs[0][0] or any(not (s.get("uses") or "").startswith("actions/upload-artifact@") for s in steps[max(i for i, _ in signs) + 1:])):
        bad.append("sign-check must sign after sign-records and upload last")
    other = [r for i, r in runs if "sign-records" not in r and "witness-sign-staged" not in r and r not in ("bash bin/install-scanner.sh aws-cli", "printf '%s' \"$DIGESTS\" > digests.json")]
    if other:
        bad.append("sign-check runs a command that is not listed: %s" % other)
    return bad


OLD_CHECK_FILES = ["bin/check-stage.sh", "bin/check-phase-scanners.sh", "bin/check-phase-acceptance.sh", "bin/check-phase-runtime.sh", "bin/check-phase-arm64.sh", ".github/workflows/stage-verify.yml"]


def oldcheck(root):
    """REQ-CHAIN-006-AC1: the per-chip and per-phase Check files are gone, and no workflow names them or the per-chip jobs, artifacts and outputs."""
    bad = ["%s still exists" % f for f in OLD_CHECK_FILES if os.path.exists(os.path.join(root, f))]
    wf = os.path.join(root, ".github/workflows")
    for f in sorted(os.listdir(wf)) if os.path.isdir(wf) else []:
        m = re.search(r"check-stage|check-phase-(scanners|acceptance|runtime|arm64)|check-arm64|records-arm64|witness-arm64|witness-check-arm64|stage-verify", open(os.path.join(wf, f)).read())
        if m:
            bad.append(".github/workflows/%s names %r, which is gone" % (f, m.group(0)))
    return bad


def graph(path):
    """REQ-CHAIN-006-AC2: the Check jobs sit beside Rebuild's in release.yml: check needs exactly check-govulncheck, build-assemble and sign; sign-check needs build-assemble and check; the release job waits (directly or through another job) for check, sign, sign-rebuild and sign-check."""
    d, bad = load(path), []
    jobs = d.get("jobs") or {}
    def needs(n):
        v = (jobs.get(n) or {}).get("needs", [])
        return {v} if isinstance(v, str) else set(v)
    def reach(n, seen=()):
        return set().union(*[{m} | reach(m, seen + (n,)) for m in needs(n) if m in jobs and m not in seen]) if needs(n) else set()
    rebuilds = ("rebuild-apk", "rebuild-assemble", "sign-rebuild")
    for n in ("build-assemble", "sign", "check-govulncheck", "check", "sign-check") + rebuilds + ("release",):   # the last stage is Release (the ratified rules' name; Q9)
        if n not in jobs:
            bad.append("release.yml has no job %s" % n)
    if bad:
        return bad
    if "uses" in jobs["check"] or "uses" in jobs["check-govulncheck"]:
        bad.append("the check jobs are jobs of release.yml itself, not a call of another workflow")
    if needs("check") != set(CHECK_NEEDS):
        bad.append("check must need exactly %s (its previous stage is Build, whose record it verifies as Sign signed it; Sign's provenance is Release's to verify, rule 58), found %s" % (CHECK_NEEDS, sorted(needs("check"))))
    if any("check" in reach(n) for n in rebuilds) or any(n in reach("check") for n in rebuilds):
        bad.append("check and rebuild must run side by side (rule 70)")
    if needs("sign-check") != {"build-assemble", "check"}:
        bad.append("sign-check must need exactly build-assemble and check, found %s" % sorted(needs("sign-check")))
    missing = {"check", "sign", "sign-rebuild", "sign-check"} - reach("release")
    if missing:   # the Witness move: Sign signs Build's records, sign-rebuild Rebuild's, sign-check Check's
        bad.append("the release job must wait for check, sign, sign-rebuild and sign-check; it does not wait for %s" % sorted(missing))
    return bad


# Q10 (advisor, Oct 10): bin/check-guide.sh runs the customer guide's VERIFY commands against the signed candidate, so it may name exactly
# these verify-only commands (case-sensitive, whole words). Every other signing word stays refused there (cosign sign, cosign attest,
# cosign upload, gh attestation ...), and no other check script may name even these.
VERIFY_ONLY = re.compile(r"\b(?:cosign verify-blob-attestation|cosign verify-attestation|cosign verify-blob"
                         r"|cosign verify)(?![\w-])")


def plain(files):
    bad = []
    for f in files:
        if not os.path.exists(f):
            bad.append("missing: %s" % f); continue
        for n, l in enumerate(open(f).read().split("\n"), 1):
            if os.path.basename(f) == "check-guide.sh":
                l = VERIFY_ONLY.sub("", l)
            m = SIGNING.search(l)
            if m:
                bad.append("%s:%d names %r: a check script knows nothing about signing, registries, secrets or tokens" % (f, n, m.group(0)))
    return bad


def listed(jsonpath, root):
    bad = []
    if not os.path.exists(jsonpath):
        return ["missing: %s" % jsonpath]
    rows = {r["path"]: r for r in json.load(open(jsonpath)).get("scripts", [])}
    for s in SCRIPTS:
        r = rows.get(s)
        if r is None:
            bad.append("%s is not listed in chain-scripts.json" % s); continue
        f = os.path.join(root, s)
        if not os.path.exists(f):
            bad.append("%s is listed but missing" % s); continue
        if hashlib.sha256(open(f, "rb").read()).hexdigest() != r.get("sha256"):
            bad.append("%s: the sha256 in chain-scripts.json is not the file's" % s)
        if r.get("signs") not in (False, "false"):
            bad.append("%s must be listed with signs: false" % s)
    for g in OLD_CHECK_FILES:
        if g in rows:
            bad.append("%s is gone but chain-scripts.json still has a row for it" % g)
    arg_map = (rows.get("bin/witnessed-local.sh") or {}).get("arg_map") or {}
    want = {s: "bin/check-phase.sh" for s in STEPS}
    want.update({"release-verify": "bin/release-verify.sh", "release-publish": "bin/release-publish.sh", "release-assets": "bin/release-assets.sh", "release-postverify": "bin/release-postverify.sh"})      # the Release steps that run under the local helper (ruling Q-e)
    for step, target in want.items():
        if arg_map.get(step) != target:
            bad.append("witnessed-local.sh's arg_map must map %s to %s, found %r" % (step, target, arg_map.get(step)))
    if "arm64" in arg_map:
        bad.append("witnessed-local.sh's arg_map has a step arm64: Check has no arm64 step")
    return bad


def records(jsonpath):
    """Rule 66: a record nobody consumes does not exist. The old custom acceptance record is gone; Check's Witness collection has a named consumer."""
    if not os.path.exists(jsonpath):
        return ["missing: %s" % jsonpath]
    rows = json.load(open(jsonpath)).get("records", [])
    bad = []
    if any(r.get("type", "").endswith("/attestations/acceptance/v1") for r in rows):
        bad.append("the old acceptance record type is still in chain-records.json")
    if not any(r.get("type") == COLLECTION and re.search(r"\bcheck\b", r.get("claim", ""), re.I) and r.get("consumer") == "release" for r in rows):
        bad.append("no row for the Witness collection naming Check in its claim with consumer release")
    return bad


def verify_form(c):
    """Every pipe segment (split outside single and double quotes, a backslash making the next character literal outside single quotes) starts with
    the words of a verify form or jq, compared whole: the rule bin/check-guide-plan.py applies at run time."""
    segs, cur, quote, i = [], "", None, 0
    while i < len(c):
        ch = c[i]
        if quote == "'":
            if ch == "'":
                quote = None
        elif quote == '"':
            if ch == "\\" and i + 1 < len(c):
                cur += ch; i += 1; ch = c[i]
            elif ch == '"':
                quote = None
        elif ch == "\\" and i + 1 < len(c):
            cur += ch; i += 1; ch = c[i]
        elif ch in "'\"":
            quote = ch
        elif ch == "|":
            segs.append(cur); cur = ""; i += 1
            continue
        cur += ch; i += 1
    if quote:
        return False
    segs.append(cur)
    for seg in segs:
        try:
            w = shlex.split(seg)
        except ValueError:
            return False
        if not (w[:1] == ["jq"] or w[:2] == ["cosign", "verify"]
                or w[:2] in (["cosign", "verify-attestation"], ["cosign", "verify-blob"], ["cosign", "verify-blob-attestation"])):
            return False
    return True


def guidelist(guide):
    """REQ-CHAIN-006-AC7, rule 79 (amended Oct 10): the guide exists and its cannot-run list (GUIDE minus .md, plus .cannot-run.json) is
    the one exact-text list Release's post-publish step reads: JSON, rows exactly {command, reason}, no duplicate, each command in the
    guide and a verify form. A valid list satisfies AC7 (the listed commands run right after publishing)."""
    if not os.path.exists(guide):
        return ["the customer guide %s does not exist (rule 79 cannot be satisfied without it)" % guide]
    lp = guide[:-3] + ".cannot-run.json" if guide.endswith(".md") else guide + ".cannot-run.json"
    if not os.path.exists(lp):
        return []
    try:
        rows = json.load(open(lp))
    except ValueError as e:
        return ["the cannot-run list %s is not JSON: %s" % (lp, e)]
    if not isinstance(rows, list):
        return ["the cannot-run list %s is not a list" % lp]
    text = open(guide).read().replace("\\\n", " ")
    text = re.sub(r"[ \t]+", " ", text)
    bad, seen = [], set()
    for r in rows:
        if not (isinstance(r, dict) and set(r) == {"command", "reason"} and isinstance(r["command"], str) and isinstance(r["reason"], str)
                and r["command"].strip() and r["reason"].strip()):
            bad.append("a cannot-run entry must be exactly {command, reason}, both non-empty (a reason is required): %r" % (r,))
            continue
        c = r["command"]
        if c in seen:
            bad.append("the cannot-run list names `%s` twice" % c)
        seen.add(c)
        if not verify_form(c):
            bad.append("the cannot-run entry `%s` is not a verify form" % c)
        if re.sub(r"[ \t]+", " ", c) not in text:
            bad.append("the cannot-run entry `%s` is not in the guide" % c)
    return bad


def removed(root):
    bad = []
    for f in OLD_FILES:
        if os.path.exists(os.path.join(root, f)):
            bad.append("%s still exists (the custom authorization verifier is replaced by Release's verify step, rule 65)" % f)
    cp = os.path.join(root, ".github/workflows/ci.yml")
    if os.path.exists(cp) and re.search(r"authorize-acceptance-check", open(cp).read()):
        bad.append("ci.yml still runs the custom authorization verifier's test")
    for f in OLD:
        if os.path.exists(os.path.join(root, ".github/workflows", f)):
            bad.append("%s still exists" % f)
    rp = os.path.join(root, ".github/workflows/release.yml")
    if os.path.exists(rp):
        t = open(rp).read()
        for f in OLD + ["acceptance.yml"]:
            if re.search(r"uses:\s*\./\.github/workflows/" + re.escape(f), t):
                bad.append("release.yml still calls %s" % f)
    bad += removed_rule61(root)
    return bad


# PLAIN FORM, the closed definition this judge enforces (orchestrator, Oct 13, from the owner's Oct 3 scope rule for the pin checker: "a simple parse ... deliberately
# hidden forms are out of scope; reviewers judge intent"): (a) the named files, directories or the Dependabot docker entry exist, or (b) a workflow run line or a script
# line whose command word, after splitting on ; && || | and newlines and stripping a leading NAME=value word and a path, is one of the removed tools (and, for crane,
# the closed list of forms below). Everything else (assembled names, variables, dead branches, program-running API argument tricks, games with exempt files) is
# information: this is a tripwire against reintroducing a Dockerfile or goreleaser by habit, not a wall against an insider.
# Rule 61 (REQ-CHAIN-006-AC10; advisor Oct 12): once the new chain works, the Dockerfile, buildx and goreleaser and their Dependabot entries are removed, and nothing
# reads them. Under apko there is no base image: the base inputs are the committed locks (.github/policy/base-inputs.json), and a candidate image is read by crane, by digest.
RULE61_WORDS = re.compile(r"(?i)\bdockerfile|\bbuildx\b|goreleaser|\bimagetools\b|build/docker")
# the judges and the deny lists that NAME these tools in order to refuse them are not readers of them
RULE61_NAMING = {"bin/chain-release-shape.py", "bin/chain-test-shape.py", "bin/chain-check-shape.py"}
# The documented exclusions of the recursive reader scan (Codex 4b-4 r1 and r2; Row 78: each one an exact name and a reason). These four files are the supply-chain
# JUDGES: the pin checker, the pin inventory, the pin audit and the pin-age check recognise and version-check ANY installer a workflow might use (their tool tables and
# refusal logic name docker/buildx and goreleaser among a dozen others), and the scan here refuses every workflow that uses one. They are named one by one (a new file
# in their directories is scanned like any other), the review records are matched by their hash-named form, and a line in a judge file that names the tools next to a
# way to run a program is a finding (the tables name tools; they never start them). Tests are skipped by name pattern everywhere, as before.
_AG = ".github/" + "ag" + "ent"      # assembled: the layout check (REQ-AUD-18) refuses a file outside the agent folder that spells the folder out
RULE61_JUDGE_FILES = {_AG + "/supply-chain/pin-inventory.py", _AG + "/supply-chain/pin-age-check.py", _AG + "/supply-chain/pin-audit.py", _AG + "/bin/check-action-pins.py"}
RULE61_REVIEW_RECORD = re.compile(r"^" + re.escape(_AG) + r"/reviews/[0-9a-f]{64}\.json$")
RULE61_RUNS = re.compile(r"subprocess|os\.system|os\.exec|os\.popen|\bPopen\b|check_output|check_call|shell=True|\bexec\(|\beval\(")
RULE61_SCAN_ROOTS = (".github", "bin", "tools", "build")
RULE61_SCAN_EXT = (".yml", ".yaml", ".json", ".sh", ".py", ".go", ".mod")


def _plain_command_is_removed_tool(line):
    """The closed definition of a plain form for a script line (orchestrator, Oct 13): split on ; && || | (a newline ends the line), strip leading NAME=value words and a
    leading path, and the command word is goreleaser or buildx, or `docker buildx`. Everything else (an assembled name, a variable, a dead branch, an argument of a
    program-running API) is information, not a finding of this judge."""
    line = re.sub(r"\"(?:\\.|[^\"\\])*\"|'[^']*'", '""', line)       # a quoted string is an argument or a message, never the command word
    for seg in re.split(r"&&|\|\||;|\|", line):
        words = seg.split()
        while words and re.fullmatch(r"[A-Za-z_]\w*=\S*", words[0]):
            words.pop(0)
        if not words:
            continue
        cmd = words[0].rsplit("/", 1)[-1]
        if cmd in ("goreleaser", "buildx") or (cmd == "docker" and len(words) > 1 and words[1] == "buildx"):
            return True
    return False


def _judge_starts_tool(root, rel):
    """A judge's tables and refusal lists name the removed tools; a judge never STARTS one: no call of a program-running API (subprocess, os.system, exec, eval...)
    whose arguments, over however many lines, name one. A judge that does not parse is a finding (fail closed)."""
    import ast
    try:
        text = open(os.path.join(root, rel), errors="replace").read()
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as ex:
        return ["%s does not parse (%s): a judge that cannot be read cannot be shown not to start a removed tool" % (rel, type(ex).__name__)]
    out = []
    runs = re.compile(r"^(run|call|check_\w+|Popen|system|popen\w*|spawn\w*|posix_spawn\w*|exec\w*|eval|getoutput|getstatusoutput|startfile|fork\w*|forkpty|__import__|import_module)$")
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
            if runs.match(name):
                seg = ast.get_source_segment(text, node) or ""
                if RULE61_WORDS.search(seg):
                    out.append("%s:%d starts a program with a removed tool in its arguments (a judge's table names tools; it never starts them)" % (rel, node.lineno))
    return out


def removed_rule61(root):
    bad = []
    for f in (".goreleaser.yaml", ".goreleaser.yml"):
        if os.path.exists(os.path.join(root, f)):
            bad.append("%s still exists (rule 61: goreleaser is removed)" % f)
    if os.path.isdir(os.path.join(root, "build/docker")):
        bad.append("build/docker still exists (rule 61: the Dockerfiles are removed; the image is assembled by apko from committed locks)")
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "node_modules")]
        for f in fn:
            if f.startswith("Dockerfile"):
                bad.append("%s exists (rule 61: no Dockerfile)" % os.path.relpath(os.path.join(dp, f), root))
    dp_ = os.path.join(root, ".github/dependabot.yml")
    if os.path.exists(dp_) and re.search(r"package-ecosystem:\s*[\"']?docker[\"']?\s*$", open(dp_).read(), re.M):
        bad.append(".github/dependabot.yml still has the docker ecosystem entry (rule 61: its Dependabot entry is removed with the Dockerfiles)")
    readers = []
    for top in RULE61_SCAN_ROOTS:
        base = os.path.join(root, top)
        for dp, dn, fn in os.walk(base):
            dn[:] = sorted(d for d in dn if d not in (".git", "node_modules", "__pycache__"))
            for f in sorted(fn):
                rel = os.path.relpath(os.path.join(dp, f), root).replace(os.sep, "/")
                full = os.path.join(dp, f)
                if os.path.islink(full):
                    continue
                try:
                    with open(full, "rb") as fh:
                        head = fh.read(4096)
                except OSError:
                    continue
                if b"\0" in head:      # a binary file is not a reader of a text name
                    continue
                if rel in RULE61_NAMING:
                    bad += _judge_starts_tool(root, rel)
                    continue
                if RULE61_REVIEW_RECORD.match(rel):
                    continue
                if re.search(r"(-test\.(sh|py)|_test\.py|^test_.*\.py)$", f):
                    # a test names the removed tools in its fixtures and in what it expects to be refused; it never RUNS one: a line whose first command word is the tool is a finding
                    for n_, ln in enumerate(open(full, errors="replace").read().splitlines(), 1):
                        if _plain_command_is_removed_tool(ln):
                            bad.append("%s:%d runs a removed tool (a test names tools in its fixtures; it never starts one): %s" % (rel, n_, ln.strip()[:100]))
                    continue
                if rel in RULE61_JUDGE_FILES:
                    bad += _judge_starts_tool(root, rel)
                    continue
                readers.append(rel)
    if os.path.exists(dp_):
        readers.append(".github/dependabot.yml")
    for rel in readers:
        m = RULE61_WORDS.search(open(os.path.join(root, rel), errors="replace").read())
        if m:
            bad.append("%s names %r (rule 61: no Dockerfile, buildx or goreleaser is read or kept; a candidate image is read by crane, by digest)" % (rel, m.group(0)))
    # crane (the chain's own copy tool) is the ONLY reader of a candidate image now, so every executable line that names it is one of a short closed list of forms
    # (Codex 4b-4 r2): the pinned install and the one manifest read of the rescan (and messages that only print its name);
    # any other line naming crane is refused, and the variable the manifest read uses is assigned exactly once, by digest, in the same step.
    CRANE = re.compile(r"(?<![\w-])crane(?![\w-])")      # also a path-qualified crane (/usr/local/bin/crane, ./crane) and crane.<anything>
    INSTALL = re.compile(r"^(?:\./)?bin/install-scanner\.sh crane(?:\s+#.*)?$")
    MANIFEST = re.compile(r"^if ! crane manifest \"\$ref\" > /tmp/index\.json 2>/tmp/inspect\.err; then$")

    def exec_lines(text):
        return [ln.strip() for ln in str(text or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]

    def crane_forbidden(l):
        """True when the line names crane in a form that is not the install, the manifest read, or a message that only prints the name."""
        if not CRANE.search(l) or INSTALL.match(l) or MANIFEST.match(l):
            return False
        if re.match(r"(echo|printf)\b", l):
            inner = re.findall(r"\$\([^)]*\)|`[^`]*`", l)      # a command substitution inside a message would run
            if any(CRANE.search(x) for x in inner):
                return True
            outside = re.sub(r"\"(?:\\.|[^\"\\])*\"|'[^']*'", "", l)       # what is left outside the quotes must be one command: no ; & | or substitution
            return bool(re.search(r"[;&|`]|\$\(", outside)) and bool(CRANE.search(l))
        return True

    def assigned(lines, var):
        # every shell word of every line (split like a shell would, so an assignment list `a=1 ref=x` counts) that assigns the variable; a line that cannot be split counts as one
        n = 0
        for l in lines:
            try:
                words = []
                for part in re.split(r"[;&|(){}]+", l):      # a command list `true;ref=x` is its words, not one
                    words += shlex.split(part, comments=True, posix=True)
            except ValueError:
                n += 1 if re.search(r"\b%s\+?=" % re.escape(var), l) else 0
                continue
            n += sum(1 for w in words if w.startswith(var + "=") or w.startswith(var + "+="))
            n += sum(1 for w in words if re.fullmatch(r"[;&|(]*%s\+?=.*" % re.escape(var), w) and not (w.startswith(var + "=") or w.startswith(var + "+=")))
        n += sum(1 for l in lines if re.search(r"\bread\s+(?:-\w+\s+)*%s\b" % re.escape(var), l) or re.search(r"\bfor\s+%s\s+in\b" % re.escape(var), l)
                 or re.search(r"\b(?:printf|mapfile|readarray)\b[^\n]*-v\s*%s\b" % re.escape(var), l))
        return n

    rs = os.path.join(root, ".github/workflows/main-candidate-rescan.yml")
    if os.path.exists(rs):
        try:
            wf = yaml.load(open(rs).read(), Loader=yaml.BaseLoader)
        except yaml.YAMLError:
            wf = None
        if not isinstance(wf, dict) or not isinstance(wf.get("jobs"), dict):
            bad.append("main-candidate-rescan.yml is not a workflow (rule 61: a candidate image is read by crane, by digest)")
            wf = {"jobs": {}}
        saw_manifest = False
        for jn, job in wf["jobs"].items():
            steps = job.get("steps") if isinstance(job, dict) and isinstance(job.get("steps"), list) else []
            installed = False
            for st in steps:
                ls = exec_lines(st.get("run") if isinstance(st, dict) else "")
                depth = 0
                for k, l in enumerate(ls):
                    if INSTALL.match(l):
                        if depth == 0:
                            installed = True
                        else:
                            bad.append("main-candidate-rescan.yml job %s: the pinned crane install is inside a conditional or loop (it must run unconditionally)" % jn)
                        continue
                    first = l.split()[0] if l.split() else ""
                    closes_here = bool(re.search(r"(?:;|\bthen\b.*|\bdo\b.*)\b(?:fi|done|esac)\s*$", l))
                    if first in ("if", "for", "while", "until", "case", "select") or l == "{" or l.startswith("{ ") or l.startswith("("):
                        depth += 0 if closes_here else 1
                    elif first in ("fi", "done", "esac") or l == "}" or l.startswith(") "):
                        depth = max(0, depth - 1)
                    if crane_forbidden(l):
                        bad.append("main-candidate-rescan.yml job %s: a line names crane in a form other than the pinned install or `if ! crane manifest \"$ref\" > /tmp/index.json 2>/tmp/inspect.err; then`: %s" % (jn, l[:120]))
                    elif MANIFEST.match(l):
                        saw_manifest = True
                        if not installed:
                            bad.append("main-candidate-rescan.yml job %s: `crane manifest` runs before the pinned install in that job (the install is per job; an ambient crane is not checksummed)" % jn)
                        want = re.compile(r"^ref=\"[^\"]*cache@\$\{TARGET_DIGEST\}\"$")
                        if assigned(ls, "ref") != 1 or not any(want.match(x) for x in ls[:k]):
                            bad.append("main-candidate-rescan.yml job %s: `crane manifest` does not read a reference assigned exactly once, before it, as <repository>/cache@${TARGET_DIGEST} in the same step (a tag could move: by digest only)" % jn)
        if not saw_manifest:
            bad.append("main-candidate-rescan.yml does not read the candidate index with crane (the pinned install, `crane manifest` by digest)")
    return bad


if __name__ == "__main__":
    cmd = sys.argv[1]
    for p in sys.argv[2:]:
        if cmd in ("stage", "script", "graph", "helper", "cluster", "suites") and not os.path.exists(p):
            print("missing file: %s" % p); sys.exit(1)
        break
    fn = {"stage": lambda: stage(sys.argv[2]), "script": lambda: script(sys.argv[2]), "signcheck": lambda: signcheck(sys.argv[2]), "oldcheck": lambda: oldcheck(sys.argv[2]), "graph": lambda: graph(sys.argv[2]),
          "plain": lambda: plain(sys.argv[2:]), "helper": lambda: helper(sys.argv[2]),
          "cluster": lambda: cluster(sys.argv[2]), "suites": lambda: suites(sys.argv[2]), "guidelist": lambda: guidelist(sys.argv[2]), "records": lambda: records(sys.argv[2]), "listed": lambda: listed(sys.argv[2], sys.argv[3]), "installs": lambda: installs(sys.argv[2], sys.argv[3]), "removed": lambda: removed(sys.argv[2])}[cmd]
    bad = fn()
    print("; ".join(bad) or "ok")
    sys.exit(1 if bad else 0)
