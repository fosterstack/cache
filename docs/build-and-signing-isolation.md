# Build and signing-key isolation

This page says how the release pipeline of this repository keeps builds apart from each other and keeps the signing key away from every build. It describes what the v0.3 release chain does; each claim links to the workflow, job or script that does it. The wording is "designed to meet" and "maps to": this is not a certification, and nothing here says the project is compliant with, or certified against, any framework.

## 1. Every build is its own job

A GitHub-hosted job runs on its own virtual machine. GitHub documents it this way: "each job runs in a fresh instance of a runner image" ([workflow syntax, runs-on](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)), and "GitHub-hosted runners execute code within ephemeral and clean isolated virtual machines" ([secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)). Permissions and secrets are set per job: a secret kept in a deployment environment is "only available to workflow jobs that reference the environment" ([deployments and environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)). The pipeline uses those facts, and only those, as its isolation unit.

| Stage | Job | What runs there | Secrets and tokens it holds |
|---|---|---|---|
| Build ([stage-build.yml](../.github/workflows/stage-build.yml)) | `apk`, one job per architecture | the apk build | no stored secret; the identity token Witness needs to attest the step; a read-only job token for admission |
| Build | `assemble` | the image assembly | no stored secret; the identity token Witness needs |
| Rebuild ([stage-reproducibility.yml](../.github/workflows/stage-reproducibility.yml)) | `apk`, one job per architecture; `assemble` | the same two steps, rebuilt from the same commit | no stored secret; the identity token Witness needs |
| Sign ([stage-sign.yml](../.github/workflows/stage-sign.yml)) | `sign` | the provenance signature | the identity token cosign needs; builds nothing |
| Check ([stage-verify.yml](../.github/workflows/stage-verify.yml)) | `check`, `check-arm64` | scanners and acceptance on Build's images | the identity token Witness needs; builds nothing |
| Release ([stage-promote.yml](../.github/workflows/stage-promote.yml)) | `compare` | the comparison of Build's and Rebuild's apks (their control and data sections; the signature of each is checked against the committed key) | contents read only: no secret, no environment, no identity token |
| Release | `verify` | verification of every earlier stage's record | the identity token Witness needs |
| Release | `release` | signing and publishing | the apk signing key, the registry credentials, write permissions (environment `release`) |

No build job holds a stored secret. Builds do not share a machine with the job that signs or publishes.

## 2. How artifacts cross jobs

Jobs pass files as workflow artifacts. Build writes a digest list and a signed Witness record of what it did. The jobs that run or decide something on a previous stage's output start by checking that stage's record against the digest list: Rebuild checks Build's record and its own apk records, Check and Sign check Build's, and the Release stage's `verify` job checks every earlier stage's record; the `release` job repeats that check on its own downloads before any credential is used ([release-verify.sh](../bin/release-verify.sh)). The Release stage's `compare` job holds no credential and so does no verification of its own: it compares Build's and Rebuild's apks first, and its result file is accepted only after `verify` has authenticated the records and checked the result against the apk digests Build attested. Images are promoted by digest, never rebuilt ([stage-promote.yml](../.github/workflows/stage-promote.yml), [release-publish.sh](../bin/release-publish.sh)). Rebuild makes its own copy of the apks and images from the same commit in its own jobs ([stage-reproducibility.yml](../.github/workflows/stage-reproducibility.yml)) and compares every item, the apk digests included, with Build's before it signs its verdict.

## 3. The signing key and the signing identities

- **The apk signing key** is stored as a secret of the `release` environment, and the workflows hand it to exactly one step: `release-apks` of the job `release` ([stage-promote.yml](../.github/workflows/stage-promote.yml), [release-apks.sh](../bin/release-apks.sh)). The registry credentials reach only the publish and sign steps.
- **The release job receives no apk or image that Rebuild made.** What it signs and publishes is Build's exact artifacts; beside them it receives only the earlier stages' records (Build, Sign, Rebuild, Check), Check's results and the small comparison result. Each apk it signs must first have exactly the digest Build attested ([release-apks.sh](../bin/release-apks.sh)).
- **The Rebuild comparison runs in a job with no secrets and no identity token** (`compare`, [stage-promote.yml](../.github/workflows/stage-promote.yml), [release-compare.py](../bin/release-compare.py)). The only thing that leaves it is a small result file, which `verify` and `release` read; `verify` accepts it only as a pass for the apk digests Build attested ([chain-verify.py](../bin/chain-verify.py), command `apk-compare`).
- **Keyless signatures** (provenance in [stage-sign.yml](../.github/workflows/stage-sign.yml); images and the release policy in [release-sign.sh](../bin/release-sign.sh), run by the release job) are made with short-lived certificates bound to the identity of the workflow job that asks for them, and are recorded in a public transparency log. The identity is that of the workflow file that runs the job: the Sign stage ([stage-sign.yml](../.github/workflows/stage-sign.yml)) and the Release stage ([stage-promote.yml](../.github/workflows/stage-promote.yml)) each have their own, and a job of the Build, Rebuild or Check workflows cannot mint a certificate that carries either of them. Jobs of one workflow file share its identity.

## 4. What these practices serve

"Serves" means the practice is designed to meet part of that requirement; it is not a statement that the whole control is met. The baseline column is NIST's own: whether the control is in the Moderate baseline of [SP 800-53B](https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final) (OSCAL profile version 5.2.0). FedRAMP publishes its own baselines, which this page does not restate. <!-- pinned: upstream -->

| Requirement | In NIST's Moderate baseline | Practice that serves it |
|---|---|---|
| SLSA v1.2 Build L3, [Isolated](https://slsa.dev/spec/v1.2/build-requirements): builds run "free of unintended external influence", including builds of the same project; no build can reach the platform's secrets; overlapping builds cannot influence one another; the build environment is ephemeral | n/a | each build is its own fresh VM (section 1); builds hold no stored secret |
| SLSA v1.2 Build L3, [Provenance is Unforgeable](https://slsa.dev/spec/v1.2/build-requirements): secret material for authenticating provenance "MUST NOT be accessible to the environment running the user-defined build steps" | n/a | provenance is signed in the Sign stage's own job with its own identity; no signing key exists in any build job (section 3) |
| NIST [SP 800-204D](https://doi.org/10.6028/NIST.SP.800-204D) 3.2.1: "isolated CI/CD environment" | n/a | section 1 | <!-- pinned: upstream -->
| NIST SP 800-204D 5.1.1: build policy that includes "a secure isolated platform"; evidence generated and verified as the build occurs | n/a | sections 1 and 2 (Witness records, verified by the next stage) | <!-- pinned: upstream -->
| NIST [SP 800-53 Rev. 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) SC-39 Process Isolation ("a separate execution domain for each executing system process") | yes | one VM per job (virtualization, which the control's discussion names) |
| SC-39(1) Hardware Separation | not in any baseline | not shown on hosted runners: see section 5 |
| SA-15 Development Process, Standards, and Tools | yes | the release chain is a documented, tested process: this page, the workflows, their wiring tests |
| SI-7 Software, Firmware, and Information Integrity; SI-7(1) Integrity Checks | yes | the records of earlier stages are verified before the stages that decide or sign use their output (section 2); apks and images are checked against attested digests before they are signed or published |
| SC-12 Cryptographic Key Establishment and Management | yes | the one long-lived key, the apk key, lives only in the `release` environment and reaches one step; other signatures use short-lived keyless certificates |
| SC-13 Cryptographic Protection | yes | the `-fips` image uses Go's FIPS 140-3 module; the release pipeline's own signing tools are not claimed to be FIPS-validated |
| Executive Order 14028 [section 4(e)(i)(A)](https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity): "using administratively separate build environments" | n/a | sections 1 and 3 |
| NIST [SSDF SP 800-218](https://doi.org/10.6028/NIST.SP.800-218) PO.5.1: "Separate and protect each environment involved in software development" | n/a | sections 1 and 3 |
| FedRAMP 20x [KSI-SVC-05](https://github.com/FedRAMP/docs-alpha/blob/main/FRMR.KSI.key-security-indicators.json) Resource Integrity: "Use cryptographic methods to validate the integrity of machine-based information resources" (release 25.12A) | n/a | signed images, provenance and attestations; digest checks above |
| FedRAMP 20x KSI-SVC-06 Secret Management: "Automate management, protection, and regular rotation of digital keys, certificates, and other secrets" | n/a | protection of the apk key (section 3); see section 5 on rotation |

## 5. Known gaps

- **No hardware separation per build.** GitHub-hosted jobs give VM-level separation. Per-build hardware separation (SC-39(1)) is not something hosted runners let us show, and we do not control the hardening of the runner image; both are listed here as one gap.
- **Provenance made inside a build job is not unforgeable by itself.** Witness attests a build step through the identity token of the job that runs it, so another step of the same job can ask for the same token. That is why the stages that decide or sign check the previous stage's record against its inputs, and `verify` checks the apk comparison against Build's attested digests, before anything is signed or published (section 2).
- **The two image variants share a job.** `assemble` builds the production and the `-fips` image in the same job, in Build and in Rebuild; splitting them is planned before the first release candidate.
- **No automated rotation of the apk signing key is claimed** (KSI-SVC-06 asks for "regular rotation").
- **The release pipeline's own signing tools are not claimed to be FIPS-validated** (SC-13).
