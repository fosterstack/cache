# Using our VEX with your scanner

Every FosterStack Cache release states, for each vulnerability we have assessed in our images, whether it
affects you. Each statement we publish says *not affected*, with the reason. We publish those
statements in three forms, generated from one file, so that your scanner stops reporting what does not affect you and
keeps reporting what does.

| File on the release page | Form | For |
|---|---|---|
| `fosterstack-cache.openvex.json` | OpenVEX | Grype, and any scanner that reads OpenVEX |
| `fosterstack-cache-v<version>.inspector-filters.json` | Amazon Inspector suppression rules | Amazon Inspector (ECR) |
| `fosterstack-cache-v<version>.csaf.json` | CSAF 2.0 VEX | Google Artifact Analysis |

The OpenVEX and CSAF files carry every statement. The Inspector file carries only the *not affected*
statements that name a package, as suppression rules: Inspector reports what affects you on its own. Each file lives on the release page of its
version, `https://github.com/fosterstack/cache/releases/tag/v<version>`, next to `release-manifest.json`.

## 1. Download the files and check they are ours

Set the version you run:

```sh
VER=X.Y.Z
```

Look up the image digest you run (`cache:${VER}` is the production image; for the FIPS image use `cache:${VER}-fips` in this command):

```sh
DIGEST=$(docker buildx imagetools inspect "ghcr.io/fosterstack/cache:${VER}" --format '{{.Manifest.Digest}}')
```

Download the three files:

```sh
curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VER}/fosterstack-cache.openvex.json"
curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VER}/fosterstack-cache-v${VER}.inspector-filters.json"
curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VER}/fosterstack-cache-v${VER}.csaf.json"
```

The release already signs a manifest of everything it ships, attached to each image as an attestation made by our
promotion workflow (the same signing [verify-images.md](verify-images.md) checks). The manifest records the sha256 of
each VEX file. Verify the attestation, pinned to that workflow and this release's tag, then check every file against
it:

```sh
(set -eo pipefail
cosign verify-attestation "ghcr.io/fosterstack/cache@${DIGEST}" \
  --type https://fosterstack.com/attestations/release-manifest/v1 \
  --certificate-identity="https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v${VER}" \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' > release-manifest.attestation.json
jq -r '.payload' release-manifest.attestation.json | base64 -d | jq '.predicate' > release-manifest.verified.json
jq -r '.vex[] | "\(.sha256)  \(.file)"' release-manifest.verified.json | sha256sum -c
)
```

Every line must say `OK`. If `cosign` reports an error, or a line says `FAILED`, stop: do not load the files.
On macOS use `shasum -a 256 -c` in place of `sha256sum -c`, and `base64 -D` in place of `base64 -d` before macOS 14.

## 2. Load them into your scanner

### Grype

```sh
grype "ghcr.io/fosterstack/cache@${DIGEST}" --vex fosterstack-cache.openvex.json
```

Use Grype 0.118.0 or later: earlier versions do not match our image's identifiers and apply none of the statements. <!-- pinned: upstream -->
Grype reads the statements at scan time and leaves out findings stated *not affected* for this image. It
changes nothing outside that scan's output.

### Amazon Inspector

Run with credentials allowed to call `inspector2:CreateFilter` in the account and region that scan your ECR copy of
our image:

```sh
(set -o pipefail; jq -c '.filters[]' "fosterstack-cache-v${VER}.inspector-filters.json" | while read -r f; do aws inspector2 create-filter --cli-input-json "$f" || exit 1; done)
```

What it does in your account: it creates Inspector suppression rules for the *not affected* statements that name a package, one
per statement, named `fosterstack-cache-v<version>-<CVE>` (when one CVE gets more than one rule, whether from one statement with several scopes or from
several statements, the second and later end in `-2`, `-3`). If no statement is suppressible the file holds no rule and the command does nothing. Each rule matches only that CVE on our exact image digests (each variant's
index and its linux/amd64 and linux/arm64 images), and only the named package. It
suppresses nothing on any other image, including other digests of your own builds on top of ours. The command stops at
the first rule Inspector refuses.

### Google Artifact Analysis

`IMAGE` is your own Artifact Registry copy of our image, copied by digest so its digest stays ours. Set it:

```sh
IMAGE=us-docker.pkg.dev/my-project/my-repo/cache
```

Then run:

```sh
jq --arg u "$IMAGE" --arg d "$DIGEST" '.product_tree.branches |= map(if (.product.product_identification_helper.purl | startswith("pkg:oci/cache@" + $d + "?")) then .name = $u else . end)' "fosterstack-cache-v${VER}.csaf.json" > vex-for-my-image.json && gcloud artifacts vulnerabilities load-vex --source=vex-for-my-image.json --uri="$IMAGE@$DIGEST"
```

The `jq` step is the only edit: it sets the name of the one product branch for your digest to your image path,
because Google applies a statement only to the image the branch names.

What it does in your project: it uploads our statements for that one image digest as VEX notes, which Artifact
Analysis shows with that image's vulnerabilities. Google's loader reads only whole-image statements: a statement
limited to one package inside the image is in the file, but the loader does not upload it, so Artifact Analysis keeps
reporting that finding. Google's VEX upload is a **preview** feature, so its behavior may change.

### Docker Scout

> **Draft, not yet verified on a published release.** This section describes how Docker Scout reads our statements from the image. It has not yet been run against a published release, so do not rely on it until this notice is gone.

Docker Scout needs no file: every release's image index carries these statements itself, as attestations attached to the image. <!-- gated: REQ-REL-010-AC6 -->
Scout applies only statements whose author you name (its default is Docker's own), so name ours. Scan the image by digest, with the `DIGEST` from step 1:

```sh
docker scout cves --vex-author '^FosterStack LLC$' "registry://ghcr.io/fosterstack/cache@${DIGEST}"
```

Scout reads the statements at scan time and leaves out findings stated *not affected* for this image. It changes nothing outside that
scan's output.

## 3. Stay current

Reload on **every release**: download the new version's files, check them (step 1), and load them (step 2).

If a statement changes, the new release's files say so, and a suppression you loaded earlier must go.

- **Grype:** use the new OpenVEX file. It reads it at each scan, so nothing old remains.
- **Amazon Inspector:** delete our earlier rules, then load the new file:

  ```sh
  (set -o pipefail; aws inspector2 list-filters --action SUPPRESS --query "filters[?starts_with(name, 'fosterstack-cache-')].arn" --output text | tr '\t' '\n' | while read -r arn; do if [ -n "$arn" ]; then aws inspector2 delete-filter --arn "$arn" || exit 1; fi; done)
  ```

  This deletes only rules whose names start with `fosterstack-cache-`.
- **Google Artifact Analysis:** load the new release's CSAF file for the image you run, with the same command.
- **Docker Scout:** nothing to load or reload; each release carries its own statements on its image.

## Other scanners

Give a scanner that reads OpenVEX the OpenVEX file above; otherwise ask us by opening an issue at
https://github.com/fosterstack/cache/issues, and say which scanner you use.
