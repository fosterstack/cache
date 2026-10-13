"""Test infrastructure (not product code) for PR 3 "Check", shared by bin/chain-check-wiring-test.sh. Judges for the shape of the Check
stage file, the order of bin/check-stage.sh, the release.yml job graph, the plainness of the check scripts and the removal of the old
acceptance stages. Each judge prints `ok` or the list of faults and exits 1 on a fault. The test first proves every judge on a
known-good fixture and on mutated copies (a judge that cannot fail proves nothing), then applies it to the real repository, which is
RED until PR 3 is implemented. Finite grammars and allowlists only; no shell analysis (final PR 1 design, advisor decision b).

  stage FILE            REQ-CHAIN-006-AC1: stage-verify.yml is an ALLOWLIST. on: workflow_call only; exactly ONE job `check`; runs-on
                        ubuntu-24.04; permissions exactly contents read + id-token write; no container, services, env, defaults, secrets,
                        strategy, needs, shell, working-directory, continue-on-error; steps EXACTLY, in order:
                          1. actions/checkout (full commit digest, persist-credentials: false, nothing else)
                          2. run: bash bin/install-scanner.sh witness, then one `bash bin/install-scanner.sh S` per listed scanner (grype, osv-scanner)
                          3. run: bash bin/install-kind.sh (REQ-CHAIN-006-AC14: kind and kubectl from exact versions and committed sha256)
                          4. digest-pinned actions/download-artifact steps, names from DOWN, explicit path outside bin/ and .github/, EXACTLY ONE
                             of them `images` (path images/; the candidates arrive as OCI tarballs, advisor ruling Q4)
                          5. THREE run steps, one line each, the only form `bash bin/witnessed.sh STEP TARGET` (TARGET = bin/check-phase-STEP.sh) with STEP
                             from the closed list scanners, acceptance, runtime, in that order (REQ-CHAIN-006-AC11: the stage never calls
                             `witness` or `timeout` itself; the helper is the one place for both)
                          6. only digest-pinned upload-artifact steps with names from UP (witness-check carries the three record directories)
  installs FILE JSON    REQ-CHAIN-006-AC4 (round 1 F2): the check job runs `bash bin/install-scanner.sh S` for every scanner S in the scanners list JSON
                        (.github/policy/scanners.json) and for none it does not list.
  helper FILE           REQ-CHAIN-006-AC9, AC11 (the RULE 68 SEAM): bin/witnessed.sh, the one helper every stage calls, is EXACTLY PR 2's canonical
                        helper (origin/pipeline-chain-build-rebuild, bin/chain-test-shape.py witnessed_lines: the token by a one-read process
                        substitution, the record witness-DIR/STEP-collection.json, the four sensitive keys) with ONE PR 3 extension: the closed step
                        list also holds scanners, acceptance and runtime (advisor ruling Q2, a step-5 revisit). At the merge with PR 2 its judge's
                        STEPS takes the same three names and this copy is deleted in favour of it.
  kind FILE             REQ-CHAIN-006-AC14: bin/install-kind.sh is exactly KIND_LINES: kind v0.33.0 and kubectl v1.37.0 for linux amd64 only (the
                        Check runner is ubuntu-24.04), each verified against its committed sha256 by sha256sum -c before it is installed.
  cluster FILE          REQ-CHAIN-006-AC14: bin/acceptance-k8s.sh creates its cluster with exactly CLUSTER (the node image by digest) and no action.
  suites FILE           REQ-CHAIN-006-AC5: acceptance.yml's gradle and maven jobs run the shared suite scripts (one copy of each suite).
  phase FILE STEP       REQ-CHAIN-006-AC1/AC3: bin/check-phase-STEP.sh is the one line `bash bin/check-stage.sh STEP`.
  script FILE           REQ-CHAIN-006-AC3: bin/check-stage.sh is `set -euo pipefail`, the two verify commands, then ONE fixed `case "$1"` with
                        exactly the phases of PHASES (each with exactly its commands, in order) and nothing else.
  records JSON          REQ-CHAIN-006-AC13 (rule 66): .github/policy/chain-records.json has no row for the old acceptance record and has a row
                        for the Witness collection naming Check as a producer and `release` as consumer. [P: the table's shape is PR 1's]
  graph FILE            REQ-CHAIN-006-AC2: release.yml job graph (check beside rebuild).
  plain FILE...         REQ-CHAIN-006-AC8: the check scripts know nothing about signing (text scan, comments and quotes included). Applied to
                        check-scan/fips/acceptance/guide; bin/check-stage.sh is judged by `script` alone (its pinned lines name Build's
                        witness-build/ directory, advisor ruling Q3).
  listed JSON ROOT      REQ-CHAIN-006-AC8: each check script is a row of .github/policy/chain-scripts.json with the sha256 the file has.
  removed ROOT          REQ-CHAIN-006-AC10 (rules 61, 65): the old acceptance stages and the custom authorization verifier are gone and
                        neither release.yml nor ci.yml calls them.
Modelled on: in-toto-witness docs/attestors/environment.md and docs/commands.md (the flags), docs/tutorials/artifact-policy.md:58-70 (what a
collection holds); PR 2's bin/chain-test-shape.py (the same flag allowlist, the same token-fetch lines)."""
import hashlib, json, os, re, shlex, sys, yaml

PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
DOWN = {"witness-build", "digests", "dist", "locks", "images"}   # Build's artifacts (Check's previous stage is Build; Sign's provenance is Release's to verify); images travel as files (OCI tarballs)
RECORD_DIRS = "witness-scanners\nwitness-acceptance\nwitness-runtime"           # PR 2's helper writes witness-STEP/STEP-collection.json
UP = {"witness-check": RECORD_DIRS, "check-results": "check-results"}   # artifact name -> the path(s) it may carry
KIND_STEP = "bash bin/install-kind.sh"
STEPS = ["scanners", "acceptance", "runtime"]
SCANNERS = ["grype", "osv-scanner"]   # the release scanners bin/check-scan.sh runs, in .github/policy/scanners.json order; the `installs` judge holds this list to that file
PHASE_TARGET = {s: "bin/check-phase-%s.sh" % s for s in STEPS}   # the judge of bin/witnessed.sh admits exactly `STEP TARGET`, so each step has a thin listed target (ruling 0384)                          # the closed list of Check's witnessed steps, in order
STEP_LIST = "apk|build|rapk|rebuild|snapshot-apk|snapshot-build|snapshot-rapk|snapshot-rebuild|scanners|acceptance|runtime|arm64|release-verify|release-apks|release-publish|release-sign|release-assets|release-postverify"   # PR 2's + PR 3's three
SENSITIVE = ["ACTIONS_ID_TOKEN_REQUEST*", "ACTIONS_RUNTIME_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "APK_RELEASE_SIGNING_KEY", "DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN", "SIGSTORE_ID_TOKEN"]   # PR 2's; never github or slsa


def witnessed_lines():
    """PR 2's canonical bin/witnessed.sh (witnessed_lines in its bin/chain-test-shape.py), with PR 3's three steps in the closed list."""
    keys = " ".join("--env-add-sensitive-key %s" % ("'%s'" % k if "*" in k else k) for k in SENSITIVE)
    return ["set -euo pipefail", 'step="$1"', "shift",
            'case "$step" in %s) ;; *) echo "witnessed: unknown step $step" >&2; exit 2 ;; esac' % STEP_LIST,
            'mkdir -p "witness-${step#snapshot-}"',
            'tok=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value)',
            'echo "::add-mask::$tok"',
            'if [ "$step" = release-sign ]; then sig=$(curl -sSf -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=sigstore" | jq -r .value); [ -n "$sig" ] && [ "$sig" != null ] || { echo "witnessed: no identity token for release-sign" >&2; exit 1; }; echo "::add-mask::$sig"; export SIGSTORE_ID_TOKEN="$sig"; fi',
            "unset ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL",
            "unset ACTIONS_RUNTIME_TOKEN ACTIONS_RUNTIME_URL",
            'exec witness run --step "$step" --signer-fulcio-url https://fulcio.sigstore.dev '
            "--signer-fulcio-oidc-issuer https://token.actions.githubusercontent.com --signer-fulcio-oidc-client-id sigstore "
            '--signer-fulcio-token-path <(printf %%s "$tok") -t https://timestamp.sigstore.dev/api/v1/timestamp '
            "-a environment,git,material,product --env-filter-sensitive-vars %s "
            '-o "witness-${step#snapshot-}/$step-collection.json" -- timeout -k 20 540 bash "$@"' % keys]


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
VERIFY = [  # bin/check-stage.sh after `set -euo pipefail` and the policy line: the verify step first (rule 58: Check's previous stage is Build), before any check (every phase re-verifies);
            # isolated and with no bytecode cache, as PR 1's Sign step runs the verifier (python3 -I -B, PR 1 r5)
    r"python3 -I -B bin/chain-verify\.py stage-start --stage check --previous build --record witness-build/build-collection\.json --digests witness-build/digests\.json --policy policy\.json",
]
PHASES = {  # rules 55, 72, 79; the phases are split so that no witnessed command nears the 9-minute cap (rule 68, amended)
    "scanners": [r"bash bin/check-scan\.sh --scanners \.github/policy/scanners\.json --digests witness-build/digests\.json --images images --archives dist --out check-results"],
    "acceptance": [r"bash bin/check-acceptance\.sh gradle --digests witness-build/digests\.json --images images --out check-results",
                   r"bash bin/check-acceptance\.sh maven --digests witness-build/digests\.json --images images --out check-results"],
    "runtime": [r"bash bin/check-acceptance\.sh egress --digests witness-build/digests\.json --images images --out check-results",
                r"bash bin/check-acceptance\.sh k8s --digests witness-build/digests\.json --images images --out check-results",
                r"bash bin/check-fips\.sh --digests witness-build/digests\.json --images images --out check-results",
                r"bash bin/check-artifacts\.sh --digests witness-build/digests\.json --images images --archives dist --out check-results",
                r"bash bin/check-guide\.sh --guide docs/verify-release\.md --digests witness-build/digests\.json --images images --out check-results"],
}
SCRIPTS = ["bin/check-stage.sh", "bin/check-phase-scanners.sh", "bin/check-phase-acceptance.sh", "bin/check-phase-runtime.sh", "bin/check-phase-arm64.sh", "bin/check-scan.sh", "bin/check-fips.sh", "bin/check-artifacts.sh", "bin/check-acceptance.sh", "bin/check-guide.sh",
           "bin/acceptance-gradle.sh", "bin/acceptance-gradle-capped.sh", "bin/acceptance-maven.sh", "bin/acceptance-maven-capped.sh",
           "bin/acceptance-egress.sh", "bin/acceptance-k8s.sh", "bin/acceptance-serve.sh", "bin/install-kind.sh"]
# REQ-CHAIN-006-AC14 (advisor ruling Q8; kind v0.33.0 release notes, https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0, 2026-08-26)
KIND_URL = "https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64"
KUBECTL_URL = "https://dl.k8s.io/release/v1.37.0/bin/linux/amd64/kubectl"
KIND_SHA = "aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d"
KUBECTL_SHA = "6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f"
NODE_IMAGE = "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5"
KIND_LINES = [
    "set -euo pipefail",
    '[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || { echo "install-kind: only linux amd64 is pinned (the Check runner is ubuntu-24.04)" >&2; exit 1; }',
    'tmp=$(mktemp -d)',
    "trap 'rm -rf \"$tmp\"' EXIT",
    'curl -fsSL -o "$tmp/kind" ' + KIND_URL,
    'curl -fsSL -o "$tmp/kubectl" ' + KUBECTL_URL,
    'printf \'%%s  %%s\\n\' %s "$tmp/kind" %s "$tmp/kubectl" | sha256sum -c -' % (KIND_SHA, KUBECTL_SHA),
    'install -m 0755 "$tmp/kind" "$tmp/kubectl" /usr/local/bin/',
    "kind version",
    "kubectl version --client",
]
CLUSTER = "kind create cluster --name fscache-accept --image " + NODE_IMAGE
SUITE_STEPS = {  # acceptance.yml: each job runs the shared suite scripts, the capped one as the results step
    "acceptance-gradle": ["bash bin/acceptance-gradle.sh", "bash bin/acceptance-gradle-capped.sh"],
    "acceptance-maven": ["bash bin/acceptance-maven.sh", "bash bin/acceptance-maven-capped.sh"],
}
SIGNING = re.compile(r"cosign|witness|gitsign|sigstore|slsa|attest|in-toto|docker\s+login|ghcr\.io|secret|ACTIONS_ID_TOKEN|ACTIONS_RUNTIME|GITHUB_TOKEN|GH_TOKEN|SNYK", re.I)
OLD = ["stage-acceptance-artifacts.yml", "stage-acceptance-egress.yml", "stage-acceptance-k8s.yml", "stage-acceptance-predicate.yml", "stage-authorize.yml"]
OLD_FILES = ["bin/authorize-acceptance-check.py", "bin/authorize-acceptance-check-test.sh"]   # the custom authorization verifier (rule 65)
COLLECTION = "https://witness.testifysec.com/attestation-collection/v0.1"


def load(path):
    return yaml.load(open(path), Loader=yaml.BaseLoader)


ARM_STEP = "arm64"
ARM_TARGET = "bin/check-phase-arm64.sh"
ARM_LINE = "bash bin/check-artifacts.sh --arch arm64 --digests witness-build/digests.json --images images --archives dist --out check-results"
ARM_DOWNLOADS = [("witness-build", "witness-build"), ("digests", "witness-build"), ("dist", "dist"), ("images", "images")]   # the same inputs as check-stage.sh verifies


def exact_steps(label, steps, want, what):
    """The exact ordered step list of a job (PR 3 round 1 F6): a digest-pinned checkout with persist-credentials: false only, a run step exactly its
    line, a digest-pinned download or upload of exactly its artifact name and path, each ONCE (a missing, a repeated, a reordered or a re-pathed step is a
    fault), and no other key in any step (an if, env or shell would change what runs)."""
    bad = []
    if len(steps) != len(want):
        bad.append("%s must have exactly its %d listed steps (%s), found %d" % (label, len(want), what, len(steps)))
    for i, (s, (kind, arg)) in enumerate(zip(steps, want), 1):
        if not isinstance(s, dict) or set(s) - {"name", "uses", "with", "run"}:
            bad.append("%s step %d: keys not allowed (an if, env or shell would change what runs): %s" % (label, i, sorted(s) if isinstance(s, dict) else s)); continue
        u, w, r = (s.get("uses") or ""), s.get("with") or {}, (s.get("run") or "").strip()
        if kind == "checkout":
            if not u.startswith("actions/checkout@") or not PIN.match(u.split(" ")[0]) or w != {"persist-credentials": "false"} or "run" in s:
                bad.append("%s step %d must be a digest-pinned checkout with persist-credentials: false only" % (label, i))
        elif kind == "run":
            if u or r != arg:
                bad.append("%s step %d must be exactly `run: %s`, found %r" % (label, i, arg, (r or u)[:80]))
        elif kind in ("down", "up"):
            action = "actions/%s-artifact@" % ("download" if kind == "down" else "upload")
            if not u.startswith(action) or not PIN.match(u.split(" ")[0]) or set(w) != {"name", "path"} or w["name"] != arg[0] or (w["path"] or "").strip() != arg[1] or "run" in s:
                bad.append("%s step %d must be a digest-pinned %s of %s %s %s only" % (label, i, "download" if kind == "down" else "upload", arg[0], "into" if kind == "down" else "carrying", arg[1].replace("\n", " ")))
    return bad


def arm_job(j):
    """REQ-CHAIN-006-AC1 (advisor 0385): the one second job, check-arm64: runs-on the literal ubuntu-24.04-arm, permissions exactly contents read +
    id-token write, no other key (no if, needs, env, strategy, container), and EXACTLY these steps in this order: a digest-pinned checkout without
    persisted credentials, the checksum-pinned Witness install, the digest-pinned downloads of witness-build, digests (into witness-build), dist and images, the one
    witnessed step `bash bin/witnessed.sh arm64 bin/check-phase-arm64.sh`, and the digest-pinned upload of witness-check-arm64 carrying witness-arm64."""
    bad = []
    if not isinstance(j, dict):
        return ["check-arm64 is not a job"]
    if set(j) != {"runs-on", "permissions", "steps"}:
        bad.append("check-arm64 may hold exactly runs-on, permissions and steps (no if, needs, env, strategy, container, name): %s" % sorted(j))
    if j.get("runs-on") != "ubuntu-24.04-arm":
        bad.append("check-arm64 must run on the literal GitHub-hosted label ubuntu-24.04-arm, got %r" % j.get("runs-on"))
    if j.get("permissions") != {"contents": "read", "id-token": "write"}:
        bad.append("check-arm64 permissions must be exactly contents read + id-token write: %s" % j.get("permissions"))
    steps = j.get("steps") or []
    want = [("checkout", None), ("run", "bash bin/install-scanner.sh witness")] + [("down", x) for x in ARM_DOWNLOADS] + \
           [("run", "bash bin/witnessed.sh %s %s" % (ARM_STEP, ARM_TARGET)), ("up", ("witness-check-arm64", "witness-arm64"))]
    bad += exact_steps("check-arm64", steps, want, "checkout, Witness install, five downloads, the arm64 witnessed step, the upload")
    return bad


def stage(path):
    d, bad = load(path), []
    on = d.get("on") or {}
    if not (isinstance(on, dict) and set(on) == {"workflow_call"}):
        bad.append("on: must be exactly workflow_call: %s" % on)
    if set(d) - {"name", "on", "permissions", "jobs"}:
        bad.append("workflow keys not allowed: %s" % sorted(set(d) - {"name", "on", "permissions", "jobs"}))
    jobs = d.get("jobs") or {}
    if list(jobs) != ["check", "check-arm64"]:
        bad.append("exactly two jobs, check and check-arm64, are required (advisor 0385), found %s" % list(jobs))
        return bad
    bad += arm_job(jobs["check-arm64"])
    j = jobs["check"]
    if set(j) - {"runs-on", "permissions", "steps", "name", "timeout-minutes"}:
        bad.append("job keys not allowed: %s" % sorted(set(j) - {"runs-on", "permissions", "steps", "name", "timeout-minutes"}))
    if j.get("runs-on") != "ubuntu-24.04":
        bad.append("check must run on the GitHub-hosted ubuntu-24.04 runner, got %r" % j.get("runs-on"))
    if j.get("permissions") != {"contents": "read", "id-token": "write"}:
        bad.append("permissions must be exactly contents read + id-token write: %s" % j.get("permissions"))
    steps = j.get("steps") or []
    text = open(path).read()
    if re.search(r"docker\s+login|\bsecrets\s*\.|secrets:|packages\s*:|attestations\s*:|ghcr\.io", text):
        bad.append("a registry login, a secret, a packages or attestations permission or a registry name appears in the file")
    kinds, names = [], []
    for s in steps:
        if set(s) - {"name", "uses", "with", "run"}:
            bad.append("step keys not allowed: %s" % sorted(set(s) - {"name", "uses", "with", "run"}))
        u = s.get("uses", "")
        if u.startswith("actions/checkout@"):
            kinds.append("checkout")
            if not PIN.match(u.split(" ")[0]) or s.get("with") != {"persist-credentials": "false"}:
                bad.append("checkout must be digest-pinned with persist-credentials: false only")
        elif u.startswith("actions/download-artifact@"):
            kinds.append("down")
            w = s.get("with") or {}
            if not PIN.match(u.split(" ")[0]) or w.get("name") not in DOWN or set(w) != {"name", "path"} or re.match(r"^(bin|\.github|\.|/|\.\.)(/|$)", w.get("path", ".")):
                bad.append("download-artifact must be digest-pinned, name in %s, an explicit path outside bin/ and .github/: %s" % (sorted(DOWN), w))
        elif u.startswith("actions/upload-artifact@"):
            kinds.append("up")
            w = s.get("with") or {}
            if not PIN.match(u.split(" ")[0]) or UP.get(w.get("name")) != (w.get("path") or "").strip() or set(w) != {"name", "path"}:
                bad.append("upload-artifact must be digest-pinned, name and path from %s (witness-check carries witness-records/): %s" % (UP, w))
        elif u:
            bad.append("uses not allowed in the Check stage: %s" % u)
        elif (s.get("run") or "").strip() in ["bash bin/install-scanner.sh " + n for n in ["witness"] + SCANNERS]:
            kinds.append("install")
        elif (s.get("run") or "").strip() == KIND_STEP:
            kinds.append("kind")
        elif "run" in s:
            kinds.append("witnessed")
            m = re.fullmatch(r"bash bin/witnessed\.sh ([a-z]+) (bin/check-phase-[a-z]+\.sh)", (s["run"] or "").strip())
            if not m or PHASE_TARGET.get(m.group(1)) != m.group(2):
                bad.append("a run step must be exactly `bash bin/witnessed.sh STEP TARGET` with TARGET the phase target of STEP, %s (no witness, timeout or other command in the stage): %r" % (PHASE_TARGET, (s["run"] or "")[:80]))
            else:
                names.append(m.group(1))
        else:
            bad.append("a step with neither uses nor run")
    want = ["checkout", "install"] + ["install"] * len(SCANNERS) + ["kind"]
    k = len(want)
    got_down = [x for x in kinds if x == "down"]
    body = [x for x in kinds if x != "down"]
    if body[:k] != want or body[k:k + 3] != ["witnessed"] * 3 or any(x != "up" for x in body[k + 3:]) or len(body) < k + 4:
        bad.append("steps must be checkout, install Witness, install each listed scanner, install kind (bash bin/install-kind.sh), downloads, THREE witnessed steps, uploads (in that order); got %s" % kinds)
    if "kind" in kinds and "down" in kinds and kinds.index("down") < kinds.index("kind"):
        bad.append("the downloads come after the installs")
    want_c = [("checkout", None), ("run", "bash bin/install-scanner.sh witness")] + [("run", "bash bin/install-scanner.sh " + s) for s in SCANNERS] + [("run", KIND_STEP)] + [("down", x) for x in ARM_DOWNLOADS] + \
             [("run", "bash bin/witnessed.sh %s %s" % (n, PHASE_TARGET[n])) for n in STEPS] + [("up", ("witness-check", RECORD_DIRS)), ("up", ("check-results", "check-results"))]
    bad += exact_steps("check", steps, want_c, "checkout, Witness install, one install per listed scanner, kind install, four downloads, the three witnessed steps, the two uploads")
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
    listed = (json.load(open(scanners_path)) or {}).get("scanners") or []
    jobs = (load(path).get("jobs") or {})
    runs = [(s.get("run") or "").strip() for s in ((jobs.get("check") or {}).get("steps") or []) if isinstance(s, dict)]
    got = [r.split(" ")[-1] for r in runs if r.startswith("bash bin/install-scanner.sh ")]
    bad = []
    for s in listed:
        if "bash bin/install-scanner.sh " + s not in runs:
            bad.append("scanners.json lists %s but the check job has no step `bash bin/install-scanner.sh %s`" % (s, s))
    for g in got:
        if g != "witness" and g not in listed:
            bad.append("the check job installs %s (`bash bin/install-scanner.sh %s`), which scanners.json does not list" % (g, g))
    return bad


def helper(path):
    """The rule 68 seam: bin/witnessed.sh is exactly PR 2's canonical helper with PR 3's three steps (witnessed_lines)."""
    raw = open(path, newline="").read()
    commands, faults = commands_of(raw)
    if commands and commands[0].startswith("#!"):
        commands = commands[1:]
    return ["control character %s in the helper" % c for c in control_chars(raw)] + faults + compare(commands, witnessed_lines(), "the helper")


def kind(path):
    """REQ-CHAIN-006-AC14: bin/install-kind.sh is exactly KIND_LINES (exact versions, amd64 only, committed sha256, checked before install)."""
    raw = open(path, newline="").read()
    commands, faults = commands_of(raw)
    return ["control character %s in the installer" % c for c in control_chars(raw)] + faults + compare(commands, KIND_LINES, "the kind installer")


def cluster(path):
    """REQ-CHAIN-006-AC14: the k8s suite creates its cluster with exactly CLUSTER, once, and names no kind action."""
    text = open(path).read()
    lines = [l.strip() for l in text.split("\n")]
    bad = []
    creates = [l for l in lines if re.search(r"\bkind\s+create\s+cluster\b", l)]
    if creates != [CLUSTER]:
        bad.append("the cluster must be created exactly once, as %r (the node image by digest); found %s" % (CLUSTER, creates))
    if re.search(r"helm/kind-action|kind-action", text):
        bad.append("the k8s suite names a kind action (kind and kubectl come from bin/install-kind.sh)")
    return bad


def suites(path):
    """REQ-CHAIN-006-AC5: acceptance.yml's gradle and maven jobs run the shared suite scripts, the capped one as the results step."""
    d, bad = load(path), []
    jobs = d.get("jobs") or {}
    for job, want in SUITE_STEPS.items():
        steps = (jobs.get(job) or {}).get("steps") or []
        runs = [(s.get("run") or "").strip() for s in steps if "run" in s]
        got = [r for r in runs if r.startswith("bash bin/acceptance-")]
        if got != want:
            bad.append("%s must run %s in that order, found %s" % (job, want, got))
        res = [s for s in steps if s.get("id") == "results"]
        if len(res) != 1 or (res[0].get("run") or "").strip() != want[-1]:
            bad.append("%s: the results step must be the one that runs %s" % (job, want[-1]))
    return bad


def script(path):
    """bin/check-stage.sh: set -euo pipefail, the two verify commands, then ONE fixed case "$1" with exactly the PHASES. Nothing else."""
    bad = []
    lines = [l.strip() for l in open(path).read().split("\n") if l.strip() and not l.strip().startswith("#")]
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    want = [("lit", "set -euo pipefail"), ("rx", POLICY)] + [("rx", r) for r in VERIFY] + [("lit", 'case "$1" in')]
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


def phase(path, step):
    """REQ-CHAIN-006-AC1/AC3 (ruling 0384): the thin target of a witnessed step is ONE command line, `bash bin/check-stage.sh STEP`, and nothing else."""
    if step not in STEPS + [ARM_STEP]:
        return ["unknown phase %r" % step]
    raw = open(path, newline="").read()
    lines = [l for l in raw.split("\n") if l.strip() and not l.strip().startswith("#")]
    bad = ["control character %s in the target" % c for c in control_chars(raw)]
    if lines and lines[0].startswith("#!"):
        lines = lines[1:]
    if step == ARM_STEP:
        # rule 58: set -euo pipefail, the policy line, the verification of Build's record (isolated), THEN the artifact checks on the digest file verified
        want = [("lit", "set -euo pipefail"), ("rx", POLICY)] + [("rx", r) for r in VERIFY] + [("lit", ARM_LINE)]
        if len(lines) != len(want):
            bad.append("the arm64 target must be exactly set -euo pipefail, the policy line, the verification of Build's record and the artifact checks (%d lines), found %d" % (len(want), len(lines)))
        for i, (k, w) in enumerate(want):
            got = lines[i] if i < len(lines) else "<missing>"
            if (k == "lit" and got != w) or (k == "rx" and not re.fullmatch(w, got)):
                bad.append("the arm64 target is not exactly the pinned form at line %d: %s" % (i + 1, got[:100])); break
        return bad
    one = "bash bin/check-stage.sh %s" % step
    if lines != [one]:
        bad.append("the target must be exactly the one line `%s`, found %s" % (one, [l[:80] for l in lines]))
    return bad


def graph(path):
    d, bad = load(path), []
    jobs = d.get("jobs") or {}
    def needs(n):
        v = (jobs.get(n) or {}).get("needs", [])
        return {v} if isinstance(v, str) else set(v)
    for n in ("build", "sign", "rebuild", "check", "release"):   # the last stage is Release (the ratified rules' name; Q9)
        if n not in jobs:
            bad.append("release.yml has no job %s" % n)
    if bad:
        return bad
    if (jobs["check"].get("uses") or "") != "./.github/workflows/stage-verify.yml":
        bad.append("the check job must call ./.github/workflows/stage-verify.yml")
    if needs("check") != {"build"}:
        bad.append("check must need exactly build (its previous stage; Sign's provenance is Release's to verify, rule 58), found %s" % sorted(needs("check")))
    if "check" in needs("rebuild") or "rebuild" in needs("check"):
        bad.append("check and rebuild must run side by side (rule 70)")
    if needs("release") != {"check", "rebuild", "sign"}:   # exactly PR 2's set (3e883b3): build is reached through check
        bad.append("the release job must need exactly check, rebuild and sign, found %s" % sorted(needs("release")))
    return bad


# Q10 (advisor, Oct 10): bin/check-guide.sh runs the customer guide's VERIFY commands against the signed candidate, so it may name exactly
# these verify-only commands (case-sensitive, whole words). Every other signing word stays refused there (cosign sign, cosign attest,
# cosign upload, gh attestation download ...), and no other check script may name even these.
VERIFY_ONLY = re.compile(r"\b(?:cosign verify-blob-attestation|cosign verify-attestation|cosign verify-blob|cosign verify|gh attestation verify)(?![\w-])")


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
        if not (w[:1] == ["jq"] or w[:2] == ["cosign", "verify"] or w[:3] == ["gh", "attestation", "verify"]
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
    return bad


if __name__ == "__main__":
    cmd = sys.argv[1]
    for p in sys.argv[2:]:
        if cmd in ("stage", "script", "graph", "helper", "kind", "cluster", "suites") and not os.path.exists(p):
            print("missing file: %s" % p); sys.exit(1)
        break
    fn = {"stage": lambda: stage(sys.argv[2]), "script": lambda: script(sys.argv[2]), "phase": lambda: phase(sys.argv[2], sys.argv[3]), "graph": lambda: graph(sys.argv[2]),
          "plain": lambda: plain(sys.argv[2:]), "helper": lambda: helper(sys.argv[2]), "kind": lambda: kind(sys.argv[2]),
          "cluster": lambda: cluster(sys.argv[2]), "suites": lambda: suites(sys.argv[2]), "guidelist": lambda: guidelist(sys.argv[2]), "records": lambda: records(sys.argv[2]), "listed": lambda: listed(sys.argv[2], sys.argv[3]), "installs": lambda: installs(sys.argv[2], sys.argv[3]), "removed": lambda: removed(sys.argv[2])}[cmd]
    bad = fn()
    print("; ".join(bad) or "ok")
    sys.exit(1 if bad else 0)
