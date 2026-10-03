# Using our VEX with your scanner

Every FosterStack Cache release states, for each known vulnerability that a scanner reports in our images, whether it
affects you: *not affected* (with the reason), *fixed*, *affected*, or *under investigation*. We publish those
statements in three forms, generated from one file, so that your scanner stops reporting what does not affect you and
keeps reporting what does.

| File on the release page | Form | For |
|---|---|---|
| `fosterstack-cache.openvex.json` | OpenVEX | Grype, Docker Scout, and any scanner that reads OpenVEX |
| `fosterstack-cache-v<version>.inspector-filters.json` | Amazon Inspector suppression rules | Amazon Inspector (ECR) |
| `fosterstack-cache-v<version>.csaf.json` | CSAF 2.0 VEX | Google Artifact Analysis |

All three carry the same statements. Each one lives on the release page of its version,
`https://github.com/fosterstack/cache/releases/tag/v<version>`, next to `release-manifest.json`.

## 1. Download the files and check they are ours

Set the version you run and the image digest you run (`cache:${VER}` is the production image; use the tag of the
variant you run):

```sh
VER=0.3.0
DIGEST=$(docker buildx imagetools inspect "ghcr.io/fosterstack/cache:${VER}" --format '{{.Manifest.Digest}}')
curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VER}/fosterstack-cache.openvex.json"
curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VER}/fosterstack-cache-v${VER}.inspector-filters.json"
curl -fsSLO "https://github.com/fosterstack/cache/releases/download/v${VER}/fosterstack-cache-v${VER}.csaf.json"
```

The release already signs a manifest of everything it ships, attached to each image as an attestation made by our
promotion workflow (the same signing [verify-images.md](verify-images.md) checks). The manifest records the sha256 of
each VEX file. Verify the attestation, pinned to that workflow and this release's tag, then check every file against
it:

```sh
cosign verify-attestation "ghcr.io/fosterstack/cache@${DIGEST}" \
  --type https://fosterstack.com/attestations/release-manifest/v1 \
  --certificate-identity-regexp="^https://github.com/fosterstack/cache/.github/workflows/stage-promote.yml@refs/tags/v${VER}$" \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  | head -n 1 | jq -r '.payload' | base64 -d | jq '.predicate' > release-manifest.verified.json
jq -r '.vex[] | "\(.sha256)  \(.file)"' release-manifest.verified.json | sha256sum -c
```

Every line must say `OK`. If `cosign` fails or a line says `FAILED`, do not load the file.

## 2. Load them into your scanner

### Grype

```sh
grype "ghcr.io/fosterstack/cache@${DIGEST}" --vex fosterstack-cache.openvex.json
```

Grype reads the statements at scan time and leaves out findings stated *not affected* or *fixed* for this image. It
changes nothing outside that scan's output.

### Docker Scout

```sh
mkdir -p vex && cp fosterstack-cache.openvex.json vex/
docker scout cves --vex-location ./vex "ghcr.io/fosterstack/cache@${DIGEST}"
```

Like Grype, Scout applies the statements to that scan's output only.

### Amazon Inspector

Run with credentials allowed to call `inspector2:CreateFilter` in the account and region that scan your ECR copy of
our image:

```sh
set -o pipefail; jq -ce '.filters[]' "fosterstack-cache-v${VER}.inspector-filters.json" | while read -r f; do aws inspector2 create-filter --cli-input-json "$f" || exit 1; done
```

What it does in your account: it creates one Inspector suppression rule per *not affected* or *fixed* statement,
named `fosterstack-cache-v<version>-<CVE>`. Each rule matches only that CVE on our exact image digests (each variant's
index and its linux/amd64 and linux/arm64 images), and only the named package where a statement names one. It
suppresses nothing on any other image, including other digests of your own builds on top of ours. The command stops at
the first rule Inspector refuses.

### Google Artifact Analysis

Set `IMAGE` to the path of your Artifact Registry copy of our image. Copy it by digest, so its digest stays ours.
Then run:

```sh
IMAGE=us-docker.pkg.dev/my-project/my-repo/cache
jq --arg u "$IMAGE" --arg d "$DIGEST" '.product_tree.branches |= map(if (.product.product_identification_helper.purl | startswith("pkg:oci/cache@" + $d + "?")) then .name = $u else . end)' "fosterstack-cache-v${VER}.csaf.json" > vex-for-my-image.json && gcloud artifacts vulnerabilities load-vex --source=vex-for-my-image.json --uri="$IMAGE@$DIGEST"
```

The `jq` step is the only edit: it sets the name of the one product branch for your digest to your image path,
because Google applies a statement only to the image the branch names.

What it does in your project: it uploads our statements for that one image digest as VEX notes, which Artifact
Analysis shows with that image's vulnerabilities. Google's VEX upload is a **preview** feature, so its behavior may
change.

## 3. Stay current

Reload on **every release**: download the new version's files, check them (step 1), and load them (step 2).

When a statement turns *affected*, the new release's files say so, and a suppression you loaded earlier must go.

- **Grype and Docker Scout:** use the new OpenVEX file. They read it at each scan, so nothing old remains.
- **Amazon Inspector:** delete our earlier rules, then load the new file:

  ```sh
  aws inspector2 list-filters --action SUPPRESS --query "filters[?starts_with(name, 'fosterstack-cache-')].arn" --output text | tr '\t' '\n' | while read -r arn; do [ -n "$arn" ] && aws inspector2 delete-filter --arn "$arn"; done
  ```

  This deletes only rules whose names start with `fosterstack-cache-`.
- **Google Artifact Analysis:** load the new release's CSAF file for the image you run, with the same command. It
  states the vulnerability as *known affected* for that digest.

## Other scanners

Give a scanner that reads OpenVEX the OpenVEX file above; otherwise ask us by opening an issue at
https://github.com/fosterstack/cache/issues, and say which scanner you use.
