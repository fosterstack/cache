# Everything we do for security

This is the list of security practices that run on the FosterStack Cache repository
today, one line each. Every line links to the place that goes deep: a page that
explains it, or the file that does it. [SECURITY.md](../SECURITY.md) is the short
policy (what we promise, including the patch target and how to report a
vulnerability); this page is what we do.

## Source

- **Signed commits.** The `main` branch accepts only signed commits, under a
  repository ruleset that also requires the checks on every pull request
  ([the repository's rules](https://github.com/fosterstack/cache/rules),
  [required checks](../.github/policy/required-checks.json)).
- **Signed release tags, checked first.** The release chain starts by verifying the
  tag against a list of allowed signers kept on `main`, before any repository code
  runs ([admission stage](../.github/workflows/stage-admission.yml),
  [allowed signers](../.github/policy/allowed_signers)).
- **Release tags are protected.** Creating a release tag is restricted by a
  repository rule, and a published release tag cannot be moved, updated or deleted
  ([the repository's rules](https://github.com/fosterstack/cache/rules)).
- **The merge gate runs from `main`.** The check that judges a pull request is the
  copy on `main`, not the copy in the pull request, so a change cannot edit the rule
  that judges it ([review gate](../.github/workflows/agent-review-gate.yml)).
- **CI runs a fork's code without secrets.** The CI workflow runs on
  `pull_request`, never `pull_request_target`, so a fork's code runs with GitHub's
  no-secrets treatment ([CI](../.github/workflows/ci.yml)).
- **A reserved branch for the automated auditor.** Only the auditor's delivery
  identity may push to its branch prefix, and any other pusher fails the check
  ([guard](../.github/workflows/reserved-branch-guard.yml)).

## Dependencies

- **Every action in every workflow is pinned to a full commit digest.** A tag or a
  branch reference fails the check on every pull request, and the check also reads
  the tag each digest claims to be ([pin checker](../.github/agent/bin/check-action-pins.py)).
- **Container images are named by digest.** An image a workflow runs, pulls or
  passes to an action must be a digest, never a tag, and the same checker fails
  the pull request otherwise ([pin checker](../.github/agent/bin/check-action-pins.py)).
- **A new version waits seven days.** A pull request that moves a pinned version is
  held until that version has been public for seven days, by a server-side time
  ([supply-chain workflow](../.github/workflows/supply-chain.yml)).
- **Everything we pin is checked daily.** The inventory of pinned actions and
  packages is checked once a day against published advisories and malicious-package
  reports ([supply-chain workflow](../.github/workflows/supply-chain.yml)).
- **Automated dependency review on every pull request.** Newly added dependencies
  and their advisories are listed and checked before merge ([CI](../.github/workflows/ci.yml)).
- **Updates are automated and judged.** Patch and minor updates merge after the full
  gate; a major update is read against the upstream release notes and our usage by
  an automated reviewer before anyone merges it
  ([auto-merge](../.github/workflows/dependabot-auto-merge.yml),
  [reviewer](../.github/workflows/dependabot-reviewer.yml)).
- **The Go toolchain stays on the newest patch of a supported minor.** A daily job
  proposes the bump when a newer supported release exists
  ([freshness job](../.github/workflows/go-freshness.yml)).
- **Go vulnerability analysis on every change.** `govulncheck` runs on every pull
  request and push; `gosec` and CodeQL read the code ([CI](../.github/workflows/ci.yml),
  [CodeQL](../.github/workflows/codeql.yml)).
- **Posture is measured in public.** OpenSSF Scorecard runs weekly and its badge is
  on the README ([Scorecard](../.github/workflows/scorecard.yml)).

## Build

- **One build, promoted by digest.** The release is built once; the same bytes are
  scanned, tested and promoted, and the promoted digest is asserted equal to the
  scanned digest after every copy ([release chain](../.github/workflows/release.yml)).
- **Every stage signs what it did.** Admission, build, image assembly,
  reproducibility, each scan and acceptance each sign a statement naming the exact
  digests, and the next stage verifies it on entry ([RELEASING.md](../RELEASING.md)).
- **Pinned toolchain.** The build uses the Go version from `go.mod` with downloads
  of a newer toolchain disabled, and module manifests are verified, never rewritten
  ([build stage](../.github/workflows/stage-build.yml)).
- **Distroless image, assembled by copy.** Each image variant is a base image digest
  plus the binary bytes: no shell, no package manager, no build step inside the
  image ([image stage](../.github/workflows/stage-image.yml)).
- **Assembled twice and compared.** The image assembly is repeated on a fresh runner
  and the digests must be equal ([reproducibility stage](../.github/workflows/stage-reproducibility.yml)).
- **A FIPS variant.** A `-fips` build uses Go's FIPS 140-3 validated cryptographic
  module, announces itself at startup, and the whole test suite runs in
  `fips140=only` mode on every commit ([SECURITY.md](../SECURITY.md#approved-only-cryptography)).
- **Approved-only cryptography is enforced by lint too.** Only in-boundary crypto
  imports are allowed, and third-party cryptographic code is denied outright
  ([`.golangci.yml`](../.golangci.yml)).

## Scanning

- **Scanners with different databases block every release.** The set is one list in
  the repository, each scanner blocks at every severity including unknown, and
  nothing hard-codes a name or a count ([scanner list](../.github/policy/scanners.json),
  [SECURITY.md](../SECURITY.md#nothing-ships-with-a-known-cve)).
- **Scanned on every pull request.** The pull request gate builds the same image the
  release would ship and scans it ([scan workflow](../.github/workflows/scan.yml)).
- **Four scanners, every day.** The daily rescan builds main's candidate and scans
  it with four independent scanners, then tallies how many saw each finding
  ([daily rescan](../.github/workflows/main-candidate-rescan.yml)).
- **Published images are rescanned daily.** A CVE disclosed against bytes we already
  shipped raises a tracked issue ([scanning.md](scanning.md)).
- **An automated audit reads every finding.** Each day an automated auditor reads
  every scanner finding against the code and the published VEX, and writes up what
  each one needs ([daily auditor](../.github/workflows/auditor.yml)).
- **Exceptions are published statements.** The only way to except a finding is an
  OpenVEX statement with a justification, kept in the repository and published with
  each release ([`.vex/`](../.vex/), [scanning.md](scanning.md)).
- **Scanner verdicts are signed.** Each scanner's verdict is a signed statement bound
  to the digests it scanned ([verify-images.md](verify-images.md)).

## Release

- **Signed images.** Every image is signed keylessly by the promotion workflow, in
  both registries ([verify-images.md](verify-images.md)).
- **Signed provenance.** Archives, SBOMs and the checksums file carry build
  provenance naming the CI run that made them ([verify-images.md](verify-images.md)).
- **An SBOM for every archive**, published with the release ([RELEASING.md](../RELEASING.md)).
- **The VEX document ships with every release** as `fosterstack-cache.openvex.json`
  ([RELEASING.md](../RELEASING.md#vex-statements)).
- **One authorization before anything goes public.** A single stage verifies the
  whole graph, fails closed on anything missing, and signs the approval that
  promotion requires ([authorization stage](../.github/workflows/stage-authorize.yml)).
- **The release is checked as a customer would.** After promotion the public digests
  are verified and pulled anonymously, and only then is the release published
  ([promotion stage](../.github/workflows/stage-promote.yml)).
- **Acceptance runs against the exact artifacts.** The archives and images that ship
  run the customer scenarios first: Gradle, Maven, Kubernetes and the artifact checks
  ([acceptance](../.github/workflows/acceptance.yml),
  [artifact acceptance](../.github/workflows/stage-acceptance-artifacts.yml)).

## Runtime

- **No telemetry and no outbound connections.** The server sends nothing anywhere,
  and a release test traces the candidate from its first instruction with egress
  denied to prove it ([egress acceptance](../.github/workflows/stage-acceptance-egress.yml),
  [SECURITY.md](../SECURITY.md#data-handling)).
- **No request access log.** The only per-request logging is on failure, and it never
  carries a body, a credential or a client address
  ([SECURITY.md](../SECURITY.md#data-handling)).

## Watch

- **A daily watch of what we depend on.** Newly published advisories and
  malicious-package reports about anything we pin are read every day
  ([supply-chain workflow](../.github/workflows/supply-chain.yml)).
