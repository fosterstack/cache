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

## The same statements, three ways (scanner-panel rule 10)

From the first release cut after this change, every release also carries two files
generated at release time from this one OpenVEX file (`bin/vex-forms.py`) and the
release's own image digests — never edited by hand:

| File | For | Statements |
|---|---|---|
| `fosterstack-cache.openvex.json` | scanners that read OpenVEX | the source |
| `fosterstack-cache-<version>.inspector-filters.json` | Amazon Inspector suppression rules (`aws inspector2 create-filter`, one rule per call) | one rule per suppressible statement (`not_affected`, `fixed`) and none for `affected` or `under_investigation`, each scoped by its CVE and by every released image digest |
| `fosterstack-cache-<version>.csaf.json` | `gcloud artifacts vulnerabilities load-vex` | every OpenVEX statement, as a CSAF 2.0 VEX document whose products are the released image digests |

In other words: the CSAF file carries every OpenVEX statement; the Inspector file
carries one rule per suppressible statement (not_affected, fixed) and none for
affected or under_investigation. `bin/vex-forms-test.sh` proves exactly that.

The Google VEX upload is a **preview feature** of Google Cloud
(`gcloud artifacts vulnerabilities load-vex`); whether our CSAF file loads there is
proven by the release candidate's live test (scanner-panel rule 12), not assumed.

All three files are listed, with their sha256, in the release's `release-manifest.json`,
which the release already signs and attaches to every image. That is how to check a
downloaded file is ours — no separate signature.

Our own pipeline keeps filtering every scanner's results against
`fosterstack-cache.openvex.json` itself; the generated forms are for customers' tools.

## Writing a statement

`status` and `justification` are not interchangeable, and the difference is what a
reader is entitled to check:

- **`component_not_present`** — the vulnerable component is not in the artifact at
  all. Verify against what shipped: `go version -m <binary>` lists
  every linked module, and `go.sum` / `go list -deps ./...` show the build. A module
  appearing only in `go mod graph` is *not* in the binary.
- **`vulnerable_code_not_in_execute_path`** — the component ships, but the vulnerable
  symbol is unreachable. Verify with `govulncheck`, which does the reachability
  analysis rather than matching version ranges. This is the weaker claim of the two
  and needs re-checking whenever the call graph changes.

State the evidence in `impact_statement` as a command a reader can run. A statement
that cannot be independently reproduced is an assertion, not an attestation.
