# Check the release key

Every release key is signed by one root key. Check the key before you trust a signature made with it. You need cosign and jq.

1. Fetch `release-key-root.pub` from the repository at the release tag: `.github/policy/release-key-root.pub`.
2. Download `release-key-manifest.json` and `release-key-manifest.sig` from the release assets.

```sh
cosign verify-blob --key release-key-root.pub --signature release-key-manifest.sig --insecure-ignore-tlog release-key-manifest.json
jq -r .public_key release-key-manifest.json > release.rsa.pub
```

Run the second command only if the first prints Verified OK. The second command writes the release key, `release.rsa.pub`, from the manifest.

The first command has `--insecure-ignore-tlog` because the root key is kept offline, so its signature has no log entry.

A key is refused at or after `valid_to` (`valid_to` is optional) or before `valid_from`. Compare the release's publish date with `valid_to` in the manifest.

The newest manifest and its signature for the same `key_id` are among the release assets. Verify them the same way as the first. Stop if the manifest has a `revoked_at` that is at or before the current time.
