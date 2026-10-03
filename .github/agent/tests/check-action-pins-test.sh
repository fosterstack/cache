#!/usr/bin/env bash
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
case_ run-local-tag            ok  "$head
    steps:
      - run: docker tag \"\$src\" fa-production
      - run: docker run --rm fa-production"
case_ run-local-build          ok  "$(r 'docker build -t localimg . && docker run localimg')"
case_ run-local-skopeo         ok  "$(r 'skopeo copy oci-archive:/tmp/a.oci docker-daemon:fa-debug:latest && docker run fa-debug:latest')"
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
case_ run-local-template       ok  "$head
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
echo "check-action-pins: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
