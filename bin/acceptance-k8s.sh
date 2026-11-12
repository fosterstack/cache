#!/usr/bin/env bash
# bin/acceptance-k8s.sh: the Kubernetes deployment suite (REQ-DEPLOY-003-AC1), extracted unchanged from stage-acceptance-k8s.yml
# (advisor ruling Q7; REQ-CHAIN-006-AC5) after two new steps: create the kind cluster (REQ-CHAIN-006-AC14: kind and kubectl come from
# the runner image, the node image by digest) and load the candidate. CANDIDATE_LOCAL is the candidate's local tag.
# Each step_NN below is the `run:` body of that step, byte for byte, run in its own subshell with the step's working directory, as
# GitHub runs a step (bash -eo pipefail, its own process): its exit, cd, variables and traps stay inside it, and the first failing
# step stops the suite. Only errexit and pipefail are applied here, GitHub's default for a run step (no -u: the bodies never ran with it).
set -eo pipefail
# The job env of stage-acceptance-k8s.yml, unchanged except that the pinned client image (by digest) is written out in step 6, where it is pulled.
export CLIENT_LOCAL=fscache-client:accept

# NEW (REQ-CHAIN-006-AC14, in place of the old stage's cluster action): the cluster, the node image by digest (kind v0.33.0 release notes).
create_cluster() (
kind create cluster --name fscache-accept --image kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
)

# NEW (in place of the old stage's registry pull): the candidate the Check acceptance wrapper loaded and tagged as $CANDIDATE_LOCAL.
load_candidate() (
kind load docker-image "$CANDIDATE_LOCAL" --name fscache-accept
)

# stage-acceptance-k8s.yml, job k8s, step 3: extract the documented manifests verbatim (image substituted)
step_03() (
set -euo pipefail
python3 bin/acceptance-k8s-manifests.py
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
python3 bin/acceptance-k8s-smoke.py
)

# stage-acceptance-k8s.yml, job k8s, step 6: load a pinned client image for the runner client pod
step_06() (
set -euo pipefail
docker pull -q curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 && docker tag curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69 "$CLIENT_LOCAL"
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
# Assert the NAMES the settings.gradle.kts reads are defined and
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
# The requests run through the loopback helper (REQ-SUP-001-AC24), fed on stdin to the pod's own shell (nothing is written in the pod).
lgin() { "$@" < bin/loopback-get.sh; }
# shellcheck disable=SC2016
lgin kubectl exec -i fscache-runner -- sh -c 'sh -s -- -sf -u "$FSCACHE_USERNAME:$FSCACHE_PASSWORD" -X PUT --data-binary runner-roundtrip http://fscache/runnerkey123 -o /dev/null'
got=$(lgin kubectl exec -i fscache-runner -- sh -c 'sh -s -- -sf -u "$FSCACHE_USERNAME:$FSCACHE_PASSWORD" http://fscache/runnerkey123')
[ "$got" = runner-roundtrip ] || { echo "runner-pod authenticated round-trip failed (got: $got)" >&2; exit 1; }
)

# stage-acceptance-k8s.yml, job k8s, step 10: run the documented port-forward smoke commands
step_10() (
set -euo pipefail
# Run the documented port-forward verbatim (backgrounded for CI),
# then the documented smoke commands with their doc-declared
# expected results.
bash /tmp/pf-forward >/tmp/pf.log 2>&1 &   # the documented command, written by the step above
pf=$!
trap 'kill "$pf" 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do grep -q "Forwarding from" /tmp/pf.log && break; sleep 1; done
bash /tmp/smoke-assert
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
