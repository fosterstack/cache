# Scanning FosterStack in your compliance pipeline

Every scanner in [the repo's scanner list](../.github/policy/scanners.json)
runs against a snapshot build of every release, and the current release's images are
rescanned daily; [`RELEASING.md`](../RELEASING.md) states exactly what the
release scan does and does not attach to. This page is about what to expect
when *you* scan our image, since a minimal image scans differently from a
typical distro image in ways that surprise people the first time.

## What to expect

**The production and `-fips` images report as `debian` in scanner OS
detection**, even though there's no shell, no package manager, and no way
to `apt-get` anything. Confirmed directly against a real build:

```
$ trivy image ghcr.io/fosterstack/cache:${VER}
...
Detected OS   family="debian" version="13.6"
...
┌──────────────────────────────────┬──────────┬─────────────────┐
│              Target               │   Type   │ Vulnerabilities │
├──────────────────────────────────┼──────────┼─────────────────┤
│ ghcr.io/fosterstack/cache (debian)│  debian  │        0        │
├──────────────────────────────────┼──────────┼─────────────────┤
│ usr/local/bin/fscache             │ gobinary │        0        │
└──────────────────────────────────┴──────────┴─────────────────┘
```

Google's distroless base ships an intact `/etc/os-release` deliberately
(that's exactly what scanners key OS detection on), and we never strip it. The `gobinary` row is our own compiled binary,
scanned by both tools' Go-module vulnerability catalogers directly.

## Package-DB asymmetry — expect this, it isn't a bug

A scratch/distroless image has no package database. That has an
asymmetric effect on checks:

- **"Is forbidden package X present?"** checks — pass vacuously. There's no
  package manager, so nothing is "installed" in the sense those checks
  look for.
- **"Is required package X present?"** checks — fail or error, for the same
  reason.

If you run a benchmark or policy pack written for a full-OS image (Debian,
Ubuntu, etc.) against ours, expect confusing partial results — not a
finding, just a mismatch between the benchmark's assumptions and a
minimal image. Scanner content often has no OS or platform gating by default,
so a scanner may score a scratch image against a full distro benchmark and
produce results that don't mean what they look like they mean. Don't over-read a scratch image's score against a
Debian-shaped policy without checking what each rule verifies.

## Exit codes: don't gate on the raw process exit code

Trivy and Grype's exit codes conflate "ran and found something above your
threshold" with "could not run at all" in ways that are easy to miss.
**Read per-rule verdicts from the results document (JSON/SARIF), never
gate a pipeline purely on the raw exit code** — a broken scan and a clean
scan can both look like "exit 0" or both look like "exit 1" depending on
flags, and conflating them ships a green gate that checks nothing.

## The `-debug` variant

The `:debug` tag adds a busybox shell for interactive troubleshooting; it is not the
image you deploy. Scanning it shows more than the production image, because busybox
itself carries a small package surface, and any known finding there that has no fix is
published as a VEX statement rather than hidden. The production and `-fips` images
never include busybox.

## Using our VEX files in your scanner

Each release carries our exceptions as published statements, generated from one
source ([`.vex/`](../.vex/)). Download them from the release page
(`gh release download v${VER} --repo fosterstack/cache -p 'fosterstack-cache*'`) and
check them against the signed release manifest as described in
[Verify our images](verify-images.md). Then apply the form your scanner reads:

| Your scanner | File | How |
|---|---|---|
| Grype | `fosterstack-cache.openvex.json` | `grype IMAGE --vex fosterstack-cache.openvex.json` |
| Trivy | `fosterstack-cache.openvex.json` | `trivy image --vex fosterstack-cache.openvex.json IMAGE` |
| Docker Scout | `fosterstack-cache.openvex.json` | `docker scout cves --vex-location fosterstack-cache.openvex.json --vex-author '^FosterStack LLC$' IMAGE` (see [Docker Scout](#docker-scout)) |
| Amazon Inspector | `fosterstack-cache-<version>.inspector-filters.json` | one suppression rule per statement: `aws inspector2 create-filter`, one rule per call |
| Google Artifact Analysis | `fosterstack-cache-<version>.csaf.json` | `gcloud artifacts vulnerabilities load-vex`, see [`.vex/README.md`](../.vex/README.md) for naming your image path |

The three files are generated from the same statements. The OpenVEX and CSAF files
carry every statement; the Inspector file carries one rule per `not_affected` or
`fixed` statement and none for `affected` or `under_investigation`. Google applies
whole-image statements only. [`.vex/README.md`](../.vex/README.md) has the detail.

## Suppression rules

A suppression rule in your scanner is only as trustworthy as the claim behind it,
so ours work in one direction: **every suppression traces to a published
statement**.

- **Our rules.** We keep no scanner-side ignore that stands alone. A suppression in
  our repository must cite the statement that governs it
  ([`.vex/README.md`](../.vex/README.md)), and the Inspector rules above are
  generated from the statements, never written by hand.
- **Which statements become rules.** `not_affected` and `fixed` statements become
  suppression rules. `affected` and `under_investigation` never do: those findings
  stay visible in your scanner.
- **Scoped to what we shipped.** Each rule is scoped by the CVE and by the digests
  of the release it was written for (and by package and version when the statement
  names one), so it does not hide the same CVE in a different image.
- **Your own rules.** Put the statement ID in the rule's reason or comment, so a
  reviewer on your side can trace it back to our file the same way.

## Docker Scout

Docker Scout reads OpenVEX directly. It applies only the statements whose author
matches `--vex-author` (by default Docker's own), so name ours, the author recorded in
the published file:

```sh
docker scout cves --vex-location fosterstack-cache.openvex.json \
  --vex-author '^FosterStack LLC$' \
  ghcr.io/fosterstack/cache:${VER}
```

Run it once with and once without `--vex-location` and `--vex-author`: the difference
is the set of findings that applicable `not_affected` and `fixed` statements suppress,
the same audit as in
[Reproducing our own gate](#reproducing-our-own-gate).

## Reproducing our own gate

The release pipeline's scan stage is public:
[`.github/workflows/stage-verify.yml`](../.github/workflows/stage-verify.yml) runs one
job per scanner in [the scanner list](../.github/policy/scanners.json) (today Grype and
OSV-Scanner) against the exact candidate digests: every variant and architecture, and
for Grype every release archive too. The commands below are partial examples that use
the gate's scanners and its severity policy on one public tag; they show what a scan of
that tag reports and do not cover everything the gate covers.

Grype runs in the gate at every severity with the published VEX applied. The VEX
document ships with each release as `fosterstack-cache.openvex.json` and lives in-repo
at [`.vex/`](../.vex/):

```sh
grype ghcr.io/fosterstack/cache:X.Y.Z \
  --fail-on negligible --vex fosterstack-cache.openvex.json
```

OSV-Scanner runs in the gate on the images and on the Go module manifests:

```sh
osv-scanner scan image ghcr.io/fosterstack/cache:X.Y.Z
```

Trivy is not part of the release gate; if you run it, use the same severities and the
same file:

```sh
trivy image --scanners vuln \
  --severity CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN \
  --vex fosterstack-cache.openvex.json \
  ghcr.io/fosterstack/cache:X.Y.Z
```

To see the findings without our statements applied, run Grype or Trivy without
`--vex`, or Docker Scout without `--vex-location` and `--vex-author`.
The difference between the two runs is the set of findings that applicable `not_affected`
and `fixed` statements suppress, which is how you audit them.

## Confirming the scan is the release run

Every scanner in the repo's list runs on every release, and the verdicts are in the
public CI run: the scan is the CI run, in this repository's Actions tab. See
[Verify our images](verify-images.md) for how to confirm the exact image
you pulled came from that same run.
