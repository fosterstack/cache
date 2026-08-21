# Releasing

**Releases build only in CI.** No binary, image, or tag that ships to a user
is ever produced on a developer machine — including the maintainers'. This
is a hard rule, not a preference: it's what makes the SLSA provenance and
Sigstore signatures on every release mean something (an attacker with a
laptop cannot forge a release that GitHub's own runners never built).

## Pipeline (target shape — being built out across Sprint 4)

```
build → test → scan (Trivy + Grype) → SBOM → SLSA provenance → cosign sign (keyless) → push
```

Every step happens in a GitHub Actions workflow in this repo, in that
order, visibly. A release is never pushed to GHCR before it has been
scanned — see [`ops/docs/cicd-security-baseline.md`](https://github.com/fosterstack/ops)
(private) for the full NIST SP 800-204D / DISA CHPG mapping this pipeline
is built against.

## What a release contains

- `linux/amd64` + `linux/arm64` container images, `FROM scratch` on a
  digest-pinned `gcr.io/distroless/static` base (built with `ko`), plus a
  `-debug` variant on a busybox-bearing base.
- A `-fips` variant (`GOFIPS140=v1.0.0`) once the release scaffold is in
  place — built from day one even before the Compliance tier ships, so the
  variant has release history before its first paying customer.
- Bare binaries + checksums (via `goreleaser`), for container-averse or
  air-gapped environments.
- Signed SBOM, signed provenance attestations, and a signed manifest digest
  — all Sigstore keyless (no long-lived signing key exists anywhere to
  steal).

## Verifying a release

Once the pipeline is live, this section documents the exact `cosign
verify` / `gh attestation verify` invocations. Not yet published — tracked
alongside the release workflow.

## Status

The pipeline described above is not live yet. This file is committed early,
ahead of the first workflow, so the constraint ("CI-only releases") is on
record before any release exists to violate it.
