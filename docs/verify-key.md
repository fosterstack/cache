# Check the release key

Every release key is signed by one root key. Check the key before you trust a signature made with it. You need cosign and jq.

1. Fetch `release-key-root.pub` from the repository at the release tag: `.github/policy/release-key-root.pub`.
2. Download `release-key-manifest.json` and `release-key-manifest.sig` from the release assets.

```sh
cosign verify-blob --key release-key-root.pub --signature release-key-manifest.sig release-key-manifest.json
jq -r .public_key release-key-manifest.json > release.rsa.pub
```

The first command checks the manifest against the root key. The second writes the release key, `release.rsa.pub`, from the manifest.

Compare the release's publish date with `valid_to` in the manifest; a release published after `valid_to` is refused.

Look for a newer manifest for the same `key_id`: a revoked key is refused, so use the newest manifest.
