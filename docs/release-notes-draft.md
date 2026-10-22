# DRAFT release notes for the next release (not published)

This is a draft for the owner to read rendered. Nothing here is a release, a tag or a claim until he says so. The text between the two rules is what would become the release body; the section after it is for the owner and is deleted before anything is published. Claims about the release chain and about the platforms are written for the state after the chain's landing pull request (cache#359) is merged: on `main` today the release definition still lists six archives including macOS, and the chain branch changes it to the four Linux archives (REQ-PLAT-001-AC1 there). If the chain does not land first, the platform bullet and the isolation section do not apply.

---

## Next release: Go 1.27.3<!-- pinned: upstream -->, optional HTTPS, and building and signing kept apart

This release is rebuilt with **Go 1.27.3**<!-- pinned: upstream -->. It fixes **GO-2026-6809** (CVE-2026-111943) in Go's standard library: crypto/x509 now distrusts compromised intermediate certificates. The fix ships in this release; there is no separate patch release for it. [TO ADD from pkg.go.dev/vuln/GO-2026-6809 on the day: the affected functions and a one-line description of the defect. TO ADD from this release's own VEX statement: whether the previous release is affected.]

The CA certificate bundle is also updated, to Wolfi's `ca-certificates-bundle` 20260909-r3, which removes three eMudhra roots: emSign Root CA C1, emSign ECC Root CA C3 and emSign ECC Root CA G3. This ships in this release too.

### What changes for Gradle and Maven users

- **Optional HTTPS.** Set `FSCACHE_TLS_CERT` and `FSCACHE_TLS_KEY` and the cache serves HTTPS, with TLS 1.2 as the minimum.
- **Clearer start-up.** The cache opens its listener first, warns about unknown `FSCACHE_` variables, and reports how many uploads it found.
- **Safer disk handling.** A failed recovery check, or an error while serving or shutting down, keeps the "unclean" marker so the next start checks again. Temporary files no longer share a name space with cache keys, and keys whose last part starts with `..` are stored in a fixed place.
- **Disk-trouble metrics.** `store_writable`, `store_free_bytes` and `put_errors_total{reason}` are new, and the store gauges are present from start-up.
- **One behaviour change you could notice.** Go 1.27<!-- pinned: upstream --> rejects a request with more than 500 header values with 431 Request Header Fields Too Large before it reaches the cache. Gradle and Maven build-cache clients send far fewer.
- **Platforms.** Linux on amd64 and arm64 only, for `fscache` and `fscache-fips`. There are no macOS or Windows binaries.

Upgrade by pulling the new tag or `:latest`.

### Building and signing, in plain words

Each build (one per architecture, and the assembly of the images) runs as its own job, and each job runs on a fresh virtual machine that GitHub provides and then discards. The key that signs the software packages inside the images (the package-signing key) exists in one place only, the release job's environment, and only one step in it receives the key. That job is handed only the exact files the build made, never the files from the second, independent rebuild. The comparison between the build and the rebuild runs in a job that holds no secrets and has no permission to publish. The signatures on the images and the release archives are a different thing: they use short-lived certificates tied to the workflow that made them, so no long-lived key signs them.

This is designed to meet the build-isolation asks of SLSA, NIST SP 800-53 Rev. 5 and Executive Order 14028 with its NIST guidance; we claim no certification. The page `docs/build-and-signing-isolation.md` names the specific controls and lists the known gaps.

### What this release does not do

- The jobs are separated at the level of a virtual machine, not on separate physical hardware.
- The package signing key is not rotated automatically.
- The release pipeline's own signing tools are not FIPS-validated. (The `-fips` image uses Go's FIPS 140-3 module, which is a different claim.)

See `release-manifest.json` for the evidence bundle: image digests, archive checksums, the requirements baseline, per-AC results and the transparency-log index.

---

## For the owner (delete this section before anything is published)

**Open before this can be posted**
1. The affected functions, the defect line and the VEX verdict for the previous release are not in the repository (the id GO-2026-6809 appears only in the Go 1.27.3<!-- pinned: upstream --> commit message). Take them from pkg.go.dev/vuln/GO-2026-6809 and the VEX the release run generates (`docs/using-our-vex.md` describes it). The owner decided (Oct 22, relayed by the advisor) that the fix ships in this release with no separate patch release, and that the notes name CVE-2026-111943 and GO-2026-6809 as fixed here.
2. The "building and signing" section is true only after the release chain's landing pull request (cache#359) merges. Nothing in the pipeline has been proven end to end by a real release yet: the first release candidate is the proof. Do not describe the chain as having run a release before then. (When this draft was written, the hosted build jobs were red on every chain pull request; that is the pipeline lane's work.)
3. The docs this section quotes: `docs/build-and-signing-isolation.md` is a draft pull request (cache#516) and is not merged.
4. The version and tag names are the owner's; the heading above is a placeholder.
5. The CA bundle line (the three eMudhra roots removed by `ca-certificates-bundle` 20260909-r3) is the owner's decision that all the eMudhra fixes ship in this release (Oct 22, relayed by the advisor). Check the bundle version in the image's package list on the day.

**Where each claim comes from** (pipeline lane, read from the repository)
- Optional HTTPS and TLS 1.2: REQ-TLS-001 (cache#296). Start-up order, unknown-variable warning, upload count: cache#257. Unclean marker kept: cache#295 and REQ-STORE-005-AC4/AC5. Temp-file and `..` key fixes: cache#292, cache#291. Disk metrics: cache#258; gauges seeded at start-up: cache#254.
- 431 on more than 500 header values and no macOS or Windows binaries: `docs/next-release-notes.md` (owner decisions, advisor 0115 and Oct 9).
- Go fix: the Go 1.27.3<!-- pinned: upstream --> bump (cache#464).
- Isolation: the chain's stage workflows (Build, Rebuild, Sign, Check, Release; the `compare`, `verify` and `release` jobs) as described on the isolation page.
- The list of server changes is built from commits under `cmd/` and `internal/` since the previous release; it is not a vetted complete list. Re-run `git log` from the previous tag before publishing.

**Deliberately not claimed** (do not add): macOS or Windows binaries; hardware-separated builds; automated signing-key rotation; FIPS validation of the pipeline's signing tools; the Docker Scout live check until the first release candidate has passed it; customer suppression files; any statement that the release chain has completed a real release.
