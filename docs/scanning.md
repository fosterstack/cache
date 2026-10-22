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
(that's exactly what scanners key OS detection on), and we never strip it
— see the scanner-facts source for this page,
`sprint4_scanner_input.md`. The `gobinary` row is our own compiled binary,
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
minimal image. `sprint4_scanner_input.md`'s source material for this page
also notes there is often no genuine OS/platform gating in scanner content
by default: a scanner may happily score a scratch image against a full
distro benchmark and produce results that don't mean what they look like
they mean. Don't over-read a scratch image's score against a
Debian-shaped policy without checking what each rule verifies.

## Exit codes: don't gate on the raw process exit code

Trivy and Grype's exit codes conflate "ran and found something above your
threshold" with "could not run at all" in ways that are easy to miss.
**Read per-rule verdicts from the results document (JSON/SARIF), never
gate a pipeline purely on the raw exit code** — a broken scan and a clean
scan can both look like "exit 0" or both look like "exit 1" depending on
flags, and conflating them ships a green gate that checks nothing. This
failure mode has been observed in the field.

## There is no debug image from v0.3.0 <!-- pinned: historical -->

Releases before v0.3.0 also shipped a `:debug` tag with a busybox shell; it <!-- pinned: historical -->
showed more in a scan than the production image because busybox itself
carries a package surface. From v0.3.0 the release carries two images, <!-- pinned: historical -->
production and `-fips`, and neither contains busybox, so there is no
debug variant to scan or to exclude from a gate. To troubleshoot a running
container use an ephemeral helper container instead; see [Docker
deploy](docker-deploy.md).

## Reproducing our own gate

The per-image scanners a release must pass are listed in one public file,
[`.github/policy/scanners.json`](../.github/policy/scanners.json): Grype and
OSV-Scanner. The release's Check stage runs
[`bin/check-scan.sh`](../bin/check-scan.sh), which scans the exact built
images by digest with both (Grype also scans the four Linux archives,
OSV-Scanner the Go modules) and fails when either reports anything the
published VEX does not except. The same Check stage also runs `govulncheck`
once on the tagged source, a separate Go source scan with its own policy that
the rest of this section does not describe. Pull requests are scanned by
[`scan.yml`](../.github/workflows/scan.yml) on the candidate images, with
Grype and Amazon Inspector.

The gate's policy is every severity, with the published VEX applied, and a
finding of unknown severity fails it too. The VEX document ships with each
release as `fosterstack-cache.openvex.json` and lives in-repo at
[`.vex/`](../.vex/). A Grype scan of a published image with that VEX applied:

```sh
grype ghcr.io/fosterstack/cache:X.Y.Z \
  --fail-on negligible --vex fosterstack-cache.openvex.json
```

This is a partial reproduction, not the gate itself. Grype's `--fail-on` does
not fail on a finding of unknown severity, which the gate does, so read the
findings it prints and do not rely on its exit code alone (the same advice as
in the exit-codes section above). It also does not run OSV-Scanner, and it uses
whatever vulnerability database your Grype has, where the gate refuses a
database more than 48 hours old, so a result can differ from ours on a
different day. Scanners outside the release gate, such as Trivy, are useful
cross-checks.

Run without `--vex` to see raw findings including the ones we have
publicly dispositioned — the difference between the two runs is exactly
the set of published VEX statements, which is how you audit them.

## Marketing claim, with the receipt

"Every scanner in the repo's list runs on every release, verdicts in the
public CI run" is not a claim we're asking you to take on faith — the scan
IS the CI run, public, in this repo's Actions tab. See
[Verify our images](verify-images.md) for how to confirm the exact image
you pulled came from that same run.
