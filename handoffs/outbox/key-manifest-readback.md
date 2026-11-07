# Read-back: cache key manifest + KR-CUTOVER (row 589), cache5, 2026-11-07

Branch key-manifest from origin/chain-v030 (780b7821). Nothing coded; waiting for your ack (security tier).

## What is already on chain-v030 (read at source)
- bin/chain-verify.py has check_manifest (:117), manifest_key (:202), MANIFEST_FILES (:85): root signature over the exact manifest
  bytes (openssl dgst -sha256 -verify), closed field list, key_id = sha256(DER), window vs the real clock, revoked_at <= now refuses.
  Root must be ECDSA P-256 (is_p256_spki). Only `policy make` calls it. No other script, no Check, no guide calls it.
- The three files (release-key-root.pub, release-key-manifest.json, release-key-manifest.sig) are not committed anywhere on the chain.
- bin/release-postverify.py (Check) verifies with build/keys/release.rsa.pub, which is a PLACEHOLDER (not a key). The guide
  docs/verify-release.md does the same with `--key release.rsa.pub`.
- Rebuild does not verify signatures; chain-verify.py stage-start verifies Build's record with the policy's release key.

## Design (what the historian found proven, checked against source above)
1. One verifier, reuse check_manifest. No second implementation, no test flags (--now etc.), no hash pin of the root.
2. Check (release-postverify.py): replace place_release_key's source: run check_manifest on the manifest published with the release
   (release-published/) plus the committed root; write release.rsa.pub from the manifest key only. Refuse before any listed command runs.
3. Rebuild / stage-start: verify the manifest before the record signature; the key comes from the manifest.
4. Customer guide: new first step: verify the manifest with the root (cosign verify-blob --key root.pub, or the same openssl line), then
   extract the key from it; the commands then use that key. Guide compares the release publish date to valid_to; checks the newest
   manifest for the key_id. Check's docs-snippets / cannot-run list updated to match.
5. Tests with mutants: unsigned, wrong root, tampered body, RSA/Ed25519 root, expired, not yet valid, revoked, unknown field, bad key_id,
   link/missing file, manifest absent in Check/Rebuild/guide.
6. Owner's one offline step goes in the PR body as exact commands + file paths; I create no key. Test fixtures use throwaway keys in temp dirs.

## Discrepancies I need ruled (none blocks the read-back, all change code)
A. KR-CUTOVER. The case in chain-build-wiring-test.sh (:2657) is "test-evidence/known-red.json lists no expected-red case". It is red BY
   DESIGN until the rc-proof marker PR removes the entry (known-red.json note; chain-hostile-test.sh:1421-1424 pins that text). It is not
   a key-rotation case. I cannot make it pass in this PR without breaking those. Proposal: leave KR-CUTOVER alone and add a NEW case
   "key rotation cutover" to chain-build-wiring-test.sh: old manifest window ended + new key valid passes; old key after valid_to refuses.
   Say if you meant something else.
B. Key type. The item text says #858 KMS RSA_4096. Your 11-06 correction says the release key is ECC_NIST_P256 (terraform/aws-apply/
   main.tf:326). On chain-v030 there is no terraform/ directory, and manifest_key accepts RSA-4096 ONLY (is_rsa4096_spki), while the
   apk path needs RSA. I could not read main.tf from this clone (unverified). I propose to keep manifest_key as is (it matches the chain's
   code and the apk path) and not touch the apk path, per your correction; tell me if the manifest key must become P-256 (the root is
   P-256 already).
C. Paths. Chain code and review list: release-key-root.pub / release-key-manifest.json / release-key-manifest.sig (under the keys dir
   policy make reads). Owner step 10 says build/keys/root.pub, key-manifest.json(.sig) and RSA-4096 sizes. I use the chain-code names;
   owner step 10 needs the same fix (it is in ops: your file).
D. Published asset: your 11-05 ruling has the signing job write release-signing-key.pub beside the manifest. Where the manifest and root
   are published is still open (guide marks TO-VERIFY). I propose: the release publishes release-key-manifest.json and .sig as release
   assets; the root pub is committed in the repo and pinned by customers. Confirm.
E. Clone note: my old cache clone has no origin (lane-clone refused to repair it); I work in /home/shop/work/cache5/cache-km.

Chainguard read: not applicable to a signature-format change with no image build (your 11-06 note waived it for the same reason); say if you want it.
