#!/usr/bin/env bash
# bin/acceptance-k8s.sh: the Kubernetes deployment suite (REQ-DEPLOY-003-AC1), extracted unchanged from stage-acceptance-k8s.yml
# (advisor ruling Q7; REQ-CHAIN-006-AC5) after two new steps: create the kind cluster (REQ-CHAIN-006-AC14: kind and kubectl come from
# bin/install-kind.sh, the node image by digest) and load the candidate. CANDIDATE_LOCAL is the candidate's local tag.
# Each step_NN below is the `run:` body of that step, byte for byte, run in its own subshell with the step's working directory, as
# GitHub runs a step (bash -eo pipefail, its own process): its exit, cd, variables and traps stay inside it, and the first failing
# step stops the suite. Only `set -eo pipefail` is set here, GitHub's default for a run step (no -u: the bodies never ran with it).
set -eo pipefail
# The job env of stage-acceptance-k8s.yml, unchanged: the pinned client image for the runner pod.
export CLIENT_IMAGE=curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69
export CLIENT_LOCAL=fscache-client:accept

# NEW (REQ-CHAIN-006-AC14, in place of the old stage's cluster action): the cluster, the node image by digest (kind v0.33.0 release notes).
create_cluster() (
kind create cluster --name fscache-accept --image kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
)

# NEW (in place of the old stage's registry pull): the candidate bin/check-acceptance.sh loaded and tagged as $CANDIDATE_LOCAL.
load_candidate() (
kind load docker-image "$CANDIDATE_LOCAL" --name fscache-accept
)

# stage-acceptance-k8s.yml, job k8s, step 3: extract the documented manifests verbatim (image substituted)
step_03() (
set -euo pipefail
python3 - <<'PY'
import re, os
doc = open("docs/kubernetes.md").read()
# Grab the first fenced yaml block under each documented H2.
want = ["## Secret (credentials)", "## PersistentVolumeClaim",
        "## Deployment", "## Service"]
blocks = []
for heading in want:
    i = doc.index(heading)
    m = re.search(r"```yaml\n(.*?)```", doc[i:], re.S)
    if not m:
        raise SystemExit(f"no yaml block under {heading!r}")
    blocks.append(m.group(1).rstrip())
manifest = "\n---\n".join(blocks)
# Substitute ONLY the image tag with the loaded candidate; keep
# imagePullPolicy Never so kind uses the loaded image.
manifest = manifest.replace("ghcr.io/fosterstack/cache:X.Y.Z", os.environ["CANDIDATE_LOCAL"])
manifest = manifest.replace(
    "image: " + os.environ["CANDIDATE_LOCAL"],
    "image: " + os.environ["CANDIDATE_LOCAL"] + "\n          imagePullPolicy: Never")
open("/tmp/fscache-k8s.yaml", "w").write(manifest)
print(manifest)
PY
)

# stage-acceptance-k8s.yml, job k8s, step 4: apply and wait for Ready
step_04() (
set -euo pipefail
kubectl apply -f /tmp/fscache-k8s.yaml
kubectl rollout status deploy/fscache --timeout=180s \
  || { kubectl describe pods -l app.kubernetes.io/name=fscache; kubectl logs -l app.kubernetes.io/name=fscache --tail=50; exit 1; }
)

# stage-acceptance-k8s.yml, job k8s, step 5: extract the documented runner env block and smoke commands
step_05() (
set -euo pipefail
python3 - <<'PY'
import re, os, shlex
doc = open("docs/kubernetes.md").read()

# --- The documented "In-cluster runners" env block ---------------
# The runner-side secretKeyRef mapping a CI runner pod uses to
# receive FSCACHE_USERNAME / FSCACHE_PASSWORD. We graft this block
# VERBATIM into a client pod: if the doc regresses (e.g. back to an
# envFrom shortcut, or a wrong secret key), the grafted pod's env
# is wrong and the assertions below fail.
i = doc.index("## In-cluster runners")
section = doc[i:]
yaml_blocks = re.findall(r"```yaml\n(.*?)```", section, re.S)
runner_block = next((b for b in yaml_blocks if "name: runner" in b), None)
if runner_block is None:
    raise SystemExit("no runner pod-spec yaml block under 'In-cluster runners'")
rlines = runner_block.splitlines()
env_idx = next((n for n, l in enumerate(rlines) if l.strip() == "env:"), None)
if env_idx is None:
    raise SystemExit("documented runner block has no 'env:' list (regressed to envFrom?)")
env_block = "\n".join(l for l in rlines[env_idx:] if l.strip() != "")
for name in ("FSCACHE_USERNAME", "FSCACHE_PASSWORD"):
    if name not in env_block:
        raise SystemExit("documented runner env block does not map " + name)

# The doc block's `env:` sits at 6-space indent under
# `- name: runner`; that is exactly where our container needs it,
# so it grafts in unchanged.
pod = (
    "apiVersion: v1\n"
    "kind: Pod\n"
    "metadata:\n"
    "  name: fscache-runner\n"
    "  labels:\n"
    "    app.kubernetes.io/name: fscache-runner\n"
    "spec:\n"
    "  restartPolicy: Never\n"
    "  containers:\n"
    "    - name: runner\n"
    "      image: " + os.environ["CLIENT_LOCAL"] + "\n"
    "      imagePullPolicy: Never\n"
    '      command: ["sleep", "3600"]\n'
    + env_block + "\n"
)
open("/tmp/runner-pod.yaml", "w").write(pod)
print("=== runner client pod (documented env block grafted) ===")
print(pod)

# --- The documented port-forward smoke commands ------------------
# Taken from their published text; the port-forward is backgrounded
# for CI and each curl's expected result is read from the doc's own
# `# -> ...` annotations, so a broken documented command/credential
# fails here.
sh_blocks = re.findall(r"```sh\n(.*?)```", doc, re.S)
pf_block = next(b for b in sh_blocks if "port-forward" in b)
curl_block = next(b for b in sh_blocks if "curl -s localhost" in b)
pf_cmd = next(l.strip() for l in pf_block.splitlines()
              if l.strip() and not l.strip().startswith("#"))
open("/tmp/pf-forward.sh", "w").write("#!/usr/bin/env bash\n" + pf_cmd + "\n")

raw = re.sub(r"\\\n\s*", " ", curl_block)   # join line continuations
cmds = [l.rstrip() for l in raw.splitlines()
        if l.strip() and not l.strip().startswith("#")]
lines = ["#!/usr/bin/env bash", "set -euo pipefail"]
lines.append('assert_out() { got=$(eval "$1" 2>/dev/null) || true; [ "$got" = "$2" ] || { echo "::error::documented smoke command failed: [$1] got [$got] want [$2]" >&2; exit 1; }; }')
lines.append('assert_ok() { eval "$1" >/dev/null 2>&1 || { echo "::error::documented smoke command failed: [$1]" >&2; exit 1; }; }')
for c in cmds:
    m = re.search(r"#\s*->\s*(\S+)", c)
    if m:
        lines.append("assert_out " + shlex.quote(c) + " " + shlex.quote(m.group(1)))
    else:
        lines.append("assert_ok " + shlex.quote(c))
open("/tmp/smoke-assert.sh", "w").write("\n".join(lines) + "\n")
print("=== documented port-forward: " + pf_cmd)
print("=== documented smoke assertions ===")
print("\n".join(lines))
PY
)

# stage-acceptance-k8s.yml, job k8s, step 6: load a pinned curl image for the runner client pod
step_06() (
set -euo pipefail
docker pull -q "$CLIENT_IMAGE"
docker tag "$CLIENT_IMAGE" "$CLIENT_LOCAL"
kind load docker-image "$CLIENT_LOCAL" --name fscache-accept
)

# stage-acceptance-k8s.yml, job k8s, step 7: create the documented runner client pod and wait for Ready
step_07() (
set -euo pipefail
kubectl apply -f /tmp/runner-pod.yaml
kubectl wait --for=condition=Ready pod/fscache-runner --timeout=90s \
  || { kubectl describe pod fscache-runner; exit 1; }
)

# stage-acceptance-k8s.yml, job k8s, step 8: the runner env block populates the expected variable names (values never printed)
step_08() (
set -euo pipefail
# Assert the NAMES the settings.gradle.kts reads are set and
# non-empty inside the pod; never echo the values. A regressed
# mapping (wrong names, or an envFrom shortcut) leaves these unset.
# shellcheck disable=SC2016
kubectl exec fscache-runner -- sh -c '[ -n "$FSCACHE_USERNAME" ] || { echo "FSCACHE_USERNAME is empty or unset in the runner pod" >&2; exit 1; }; [ -n "$FSCACHE_PASSWORD" ] || { echo "FSCACHE_PASSWORD is empty or unset in the runner pod" >&2; exit 1; }'
)

# stage-acceptance-k8s.yml, job k8s, step 9: an authenticated request from the runner pod round-trips
step_09() (
set -euo pipefail
# Use ONLY the credentials the documented env block injected (never
# read out-of-band from the Secret) against the cluster-internal
# Service. A broken mapping yields empty creds -> 401 -> failure.
# shellcheck disable=SC2016
kubectl exec fscache-runner -- sh -c '
  set -e
  curl -sf -u "$FSCACHE_USERNAME:$FSCACHE_PASSWORD" -X PUT --data-binary runner-roundtrip http://fscache/runnerkey123 -o /dev/null
  got=$(curl -sf -u "$FSCACHE_USERNAME:$FSCACHE_PASSWORD" http://fscache/runnerkey123)
  [ "$got" = runner-roundtrip ] || { echo "runner-pod authenticated round-trip failed (got: $got)" >&2; exit 1; }
'
)

# stage-acceptance-k8s.yml, job k8s, step 10: run the documented port-forward smoke commands
step_10() (
set -euo pipefail
# Run the documented port-forward verbatim (backgrounded for CI),
# then the documented curl smoke commands with their doc-declared
# expected results.
bash /tmp/pf-forward.sh >/tmp/pf.log 2>&1 &   # the documented command, written by the step above
pf=$!
trap 'kill "$pf" 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do grep -q "Forwarding from" /tmp/pf.log && break; sleep 1; done
bash /tmp/smoke-assert.sh
echo "REQ-DEPLOY-003-AC1: manifests + runner env block + smoke commands from docs/kubernetes.md pass"
)

# stage-acceptance-k8s.yml, job k8s, step 11: report the AC this stage asserted
step_11() (
echo 'results=[{"ac":"REQ-DEPLOY-003-AC1","result":"pass"}]' >> "$GITHUB_OUTPUT"
)

create_cluster
load_candidate
step_03
step_04
step_05
step_06
step_07
step_08
step_09
step_10
step_11
