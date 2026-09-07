# VEX statements

This directory is the **single source of truth** for every scanner exception
FosterStack Cache claims. If a CVE is reported against a release artifact and we
ship anyway, the reason is a statement in
[`fosterstack-cache.openvex.json`](fosterstack-cache.openvex.json) — nowhere else.

## The rule

No VEX statement, no exception, no push. The release gate blocks on a known CVE at
**any** severity; a published VEX statement is the only thing that changes that
outcome.

A tool-specific ignore — a `.snyk` policy entry, a scanner suppression, anything of
that shape — **must reference the statement ID that governs it** and may never stand
alone. A suppression nobody can trace back to a published claim is indistinguishable
from someone quietly turning a scanner down.

## How it is consumed

One document, many statements: adding an exception appends to `statements[]` and
increments the document's `version`. Both scanners read this file in the release
gate and in the daily rescan, so an exception applies identically at release time and
for the life of the shipped bytes:

| Scanner | How |
|---|---|
| Trivy | `TRIVY_VEX` environment variable |
| Grype | `vex:` input to `anchore/scan-action` |

It ships as a release asset, so anyone auditing an artifact gets our claims alongside
the SBOM and the provenance rather than having to take the scan result on faith.

## Writing a statement

`status` and `justification` are not interchangeable, and the difference is what a
reader is entitled to check:

- **`component_not_present`** — the vulnerable component is not in the artifact at
  all. Verify by looking at what actually shipped: `go version -m <binary>` lists
  every linked module, and `go.sum` / `go list -deps ./...` show the build. A module
  appearing only in `go mod graph` is *not* in the binary.
- **`vulnerable_code_not_in_execute_path`** — the component ships, but the vulnerable
  symbol is unreachable. Verify with `govulncheck`, which does the reachability
  analysis rather than matching version ranges. This is the weaker claim of the two
  and needs re-checking whenever the call graph changes.

State the evidence in `impact_statement` as a command a reader can run. A statement
that cannot be independently reproduced is an assertion, not an attestation.
