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
- **Signed release tags, checked first.** Build first verifies the tag signature
  against a list of allowed signers kept on `main`, then builds
  ([build jobs](../.github/workflows/release.yml),
  [allowed signers](../.github/policy/allowed_signers)).
- **Release tags are protected.** Creating a release tag is restricted by a
  repository rule, and a published release tag cannot be moved, updated or deleted
  ([the repository's rules](https://github.com/fosterstack/cache/rules)).
- **CI runs a fork's code without secrets.** The CI workflow runs on
  `pull_request`, never `pull_request_target`, so a fork's code runs with GitHub's
  no-secrets treatment ([CI](../.github/workflows/ci.yml)).
- **A reserved branch for the automated auditor.** Only the auditor's delivery
  identity may push to its branch prefix, and any other pusher fails the check
  ([guard](../.github/workflows/reserved-branch-guard.yml)).

## Dependencies

- **Every action in every workflow is pinned to a full commit digest.** A tag or a
  branch reference is refused: reviewers check every pull request for it, and the
  release audit checks it again.
- **Container images and downloads are pinned.** An image a workflow runs, pulls or
  passes to an action is named by digest, never a tag, and an outside download is
  pinned to a checksum; reviewers and the release audit check both.
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
- **Go vulnerability analysis and code scanning.** `govulncheck` runs on every pull
  request and every push to `main`. CodeQL reads the code on every pull request,
  every push to `main` and once a day. A release is accepted only
  when the CodeQL runs on that exact commit passed
  ([CI](../.github/workflows/ci.yml), [CodeQL](../.github/workflows/codeql.yml),
  [release checks](../.github/policy/required-checks.json)).
- **Posture is measured in public.** OpenSSF Scorecard runs weekly and its badge is
  on the README ([Scorecard](../.github/workflows/scorecard.yml)).

## Build

Releases are built by the release chain from v0.3.0; the lines about it below <!-- pinned: historical -->
describe that chain.

- **One build, promoted by digest.** The release is built once; the same bytes are
  scanned, tested and promoted, and the promoted digest is asserted equal to the
  scanned digest after every copy ([release chain](../.github/workflows/release.yml)).
- **Every record is signed by a stage that builds nothing.** Build, Rebuild and Check
  record what they did and hold no release signing key; the Sign stage checks and signs each
  record, and the next stage verifies it ([RELEASING.md](../RELEASING.md)).
- **Pinned toolchain.** The build uses the Go version from `go.mod` with downloads
  of a newer toolchain disabled, and module manifests are verified, never rewritten
  ([build jobs](../.github/workflows/release.yml)).
- **The Wolfi packages in the image come from our own archive.** The
  image is assembled by apko from Wolfi packages that we keep in our own archive,
  plus the project's own package, which the build job makes. A
  scheduled job refreshes the archive and a committed pointer names its digest; the
  build pulls the archive by that digest and checks every package against its
  recorded hash, so a Wolfi package that was not archived and verified cannot
  reach an image ([build jobs](../.github/workflows/release.yml),
  [refresh job](../.github/workflows/go-freshness.yml)).
- **The build tools are downloaded at a pinned version and checked.** The
  tools that make the packages and the image are fetched from their release pages
  at an exact version and verified against a checksum before they run
  ([build jobs](../.github/workflows/release.yml)).
- **Minimal image, assembled from pinned packages.** Each image variant is built
  from a few packages and the binary, with no base image and no build step inside
  the image; the production and FIPS images have no shell and no package manager
  ([build jobs](../.github/workflows/release.yml)).
- **Build, Rebuild and a no-secret compare job.** Build makes the apks
  and the images. Rebuild makes its own copy from the same commit in its own jobs,
  and a separate compare job, which holds no secret, no environment and no identity
  token, compares Build's and Rebuild's apks before the release job publishes
  ([rebuild jobs](../.github/workflows/release.yml),
  [release jobs](../.github/workflows/release.yml)).
- **Every build is its own job.** Each build, for each architecture, runs
  in a fresh virtual machine that holds no stored secret, and no build shares a
  machine with the job that signs or the job that publishes
  ([build and signing-key isolation](build-and-signing-isolation.md) explains it).
- **The signer never receives an apk or an image that Rebuild made.** The
  release job publishes Build's exact artifacts, after checking each
  against the digest Build attested; the rebuilt files only feed the comparison. Only
  the three Sign jobs and the evidence letter's `sign` job can use the signing key; the release job, builds and pull
  requests never can
  (same page, section 3).
- **Assembled twice and compared.** The image assembly is repeated on a fresh runner
  and the digests must be equal ([rebuild jobs](../.github/workflows/release.yml)).
- **A FIPS variant.** A `-fips` build uses Go's FIPS 140-3 validated cryptographic
  module, announces itself at startup, and the whole test suite runs in
  `fips140=only` mode on every pull request and every push to `main`
  ([CI](../.github/workflows/ci.yml),
  [SECURITY.md](../SECURITY.md#approved-only-cryptography)).
- **Approved-only cryptography is checked by lint too.** A lint rule denies the
  third-party cryptographic packages we name, such as `golang.org/x/crypto`, so code
  reaches for the validated module instead ([`.golangci.yml`](../.golangci.yml)).

## Scanning

- **Scanners with different databases block every release.** The set is one list in
  the repository, each scanner blocks at every severity including unknown, and
  nothing hard-codes a name or a count ([scanner list](../.github/policy/scanners.json),
  [SECURITY.md](../SECURITY.md#nothing-ships-with-a-known-cve)).
- **Scanned on every pull request, every push to `main` and every day.** The scan
  builds the same image the release would ship and scans it. A release is built and tested on its release branch
  and published only after the acceptance and persona tests pass
  ([scan workflow](../.github/workflows/scan.yml),
  [release checks](../.github/policy/required-checks.json)).
- **Four scanners, every day.** The daily rescan builds main's candidate and scans
  it with four independent scanners, Grype, Docker Scout, Amazon Inspector and
  Google Artifact Analysis, then tallies how many saw each finding
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

- **Signed images.** Every image is signed with the release key by the Sign stage and
  the signature is pushed, after it is checked, to both registries ([verify-images.md](verify-images.md)).
- **Signed provenance.** The images and archives Build made have signed build
  provenance naming the commit and the CI run that made them
  ([verify-images.md](verify-images.md)).
- **An SBOM for every archive**, published with the release ([RELEASING.md](../RELEASING.md)).
- **The VEX document ships with every release** as `fosterstack-cache.openvex.json`
  ([RELEASING.md](../RELEASING.md#vex-statements)).
- **The release stage checks every earlier stage first.** Before it publishes
  anything it verifies the tag, the release policy and each earlier stage's signed
  record, in order ([release jobs](../.github/workflows/release.yml)).
- **Builds and signing are kept apart.** Every build is its own job on its own
  virtual machine, only the Sign stage's jobs and the evidence letter's `sign` job can use the signing
  key (the release job, builds and pull requests never can), and the comparison of the rebuilt files
  runs in a job with no secrets
  ([build and signing-key isolation](build-and-signing-isolation.md)).
- **The release is checked as a customer would.** After promotion the public digests
  are verified and pulled anonymously, and only then is the release published
  ([release jobs](../.github/workflows/release.yml)).
- **The full test suite runs every night.** Every test suite that
  pull-request CI does not run, and the Gradle and Maven acceptance suites, run every
  night and on demand, never on a pull request or a push
  ([full suite](../.github/workflows/full-suite.yml)).
- **Acceptance runs against the exact artifacts.** The archives and images that ship
  run the customer scenarios first: Gradle, Maven, Kubernetes and the artifact checks
  ([check jobs](../.github/workflows/release.yml)).

## Runtime

- **No telemetry and no outbound connections.** The server sends nothing anywhere,
  and a release test traces the candidate from its first instruction with egress
  denied to prove it ([check jobs](../.github/workflows/release.yml),
  [SECURITY.md](../SECURITY.md#data-handling)).
- **No request access log.** The only per-request logging is on failure, and it never
  carries a body, a credential or a client address
  ([SECURITY.md](../SECURITY.md#data-handling)).

## Watch

- **A daily watch of what we depend on.** Newly published advisories and
  malicious-package reports about anything we pin are read every day
  ([supply-chain workflow](../.github/workflows/supply-chain.yml)).
