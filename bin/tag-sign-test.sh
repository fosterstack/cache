#!/usr/bin/env bash
# proves: REQ-REL-009-AC5, REQ-REL-009-AC6, REQ-REL-009-AC8
# bin/tag-sign.py: the two offline halves of signing a patch tag with the one release KMS key (the sign-tag job of stage-sign.yml runs
# `prepare`, then the KMS call (bin/with-aws-token.sh kms-sign) on the digest, then `assemble`). No AWS, no network: the KMS call is stood in
# for here by `openssl pkeyutl` with a fixture RSA key made at test time (RSASSA-PKCS1-v1_5 over the 32-byte sha256 digest, as KMS signs a
# DIGEST with RSASSA_PKCS1_V1_5_SHA_256). The oracle is git itself: the assembled tag is verified with `git verify-tag` against a one-line
# allowed-signers file, the same check source admission makes (bin/build-admit.py).
#
# THE CLI THIS TEST ASSUMES (bin/tag-sign.py; the one file this test needs the implementation to add; TAG_SIGN=path overrides the script):
#   tag-sign.py prepare  --tag vX.Y.Z --commit SHA40 --notes FILE --tagger 'Name <email>' --time EPOCH --object OUT --digest OUT
#       writes the annotated tag object WITHOUT a signature (what `git cat-file tag` prints minus the signature: object, type commit, tag, tagger
#       `NAME <EMAIL> EPOCH +0000`, a blank line, the notes file's bytes verbatim as the message) to --object, and to --digest the lowercase hex
#       sha256 of the OpenSSH SSHSIG signed-data blob (namespace git) over that object, one line: the digest the KMS key signs. Only a patch tag
#       vX.Y.Z with Z >= 1 is accepted (the release key signs no other tag: admission refuses it); anything else exits non-zero and writes nothing.
#   tag-sign.py assemble --object FILE --signature FILE --signer-file FILE --out OUT
#       --signature is the raw RSA signature bytes (what kms-sign writes as --out); --signer-file is a one-line allowed-signers file
#       (.github/policy/release_tag_signer: `PRINCIPAL ssh-rsa KEY`) whose key goes into the signature block. Writes to --out the --object bytes
#       followed by one `-----BEGIN SSH SIGNATURE-----` block (sig algorithm rsa-sha2-256, namespace git): the signed tag object, ready for
#       `git hash-object -t tag -w`. No ssh-rsa key in the file, or an empty signature: exit non-zero, nothing written.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
TS="${TAG_SIGN:-$root/bin/tag-sign.py}"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
for t in git ssh-keygen openssl python3; do command -v "$t" > /dev/null || { echo "FAIL $t is required"; exit 1; }; done
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
# ---- fixtures: an RSA key (the stand-in for the KMS key), another RSA key, a repo with one commit, notes as decide generates them ----
for k in kms other; do ssh-keygen -q -t rsa -b 3072 -N "" -C "$k" -f "$W/$k"; done
cp "$W/kms" "$W/kms.pem"; ssh-keygen -q -p -m PEM -N "" -f "$W/kms.pem" > /dev/null
printf 'release@fosterstack ssh-rsa %s\n' "$(cut -d' ' -f2 "$W/kms.pub")" > "$W/signer"
printf 'release@fosterstack ssh-rsa %s\n' "$(cut -d' ' -f2 "$W/other.pub")" > "$W/signer-other"
git init -q "$W/repo"; git -C "$W/repo" commit -q --allow-empty -m c; SHA=$(git -C "$W/repo" rev-parse HEAD)
NOTES_TXT=$'## v0.3.1 — patch release\n\n### Fixes\n- none (dependency or VEX maintenance only)\n\n### VEX\n- no change\n'
printf '%s' "$NOTES_TXT" > "$W/notes.md"
TAGGER='fosterstack release <release@users.noreply.github.com>'
prep() { python3 "$TS" prepare --tag "${1:-v0.3.1}" --commit "${2:-$SHA}" --notes "${3:-$W/notes.md}" --tagger "${4:-$TAGGER}" --time "${5:-1700000000}" \
           --object "${6:-$W/obj}" --digest "${7:-$W/digest}"; }
kms_sign() { # KMS stand-in: sign the hex digest file $1 as KMS does a DIGEST message, write the raw signature to $2
  python3 -c 'import sys; sys.stdout.buffer.write(bytes.fromhex(open(sys.argv[1]).read().strip()))' "$1" > "$W/digest.bin"
  openssl pkeyutl -sign -inkey "$W/kms.pem" -pkeyopt digest:sha256 -in "$W/digest.bin" -out "$2" 2> /dev/null; }
verify() { # verify OBJFILE SIGNERFILE : put the tag object into the repo and run git verify-tag as admission does; sets VOUT
  local id; id=$(git -C "$W/repo" hash-object -t tag -w "$1") || return 1
  git -C "$W/repo" update-ref refs/tags/v0.3.1 "$id"
  VOUT=$(LC_ALL=C git -C "$W/repo" -c gpg.ssh.allowedSignersFile="$2" verify-tag v0.3.1 2>&1) || return 1; }
if [ -f "$TS" ]; then ok "bin/tag-sign.py exists"
else bad "bin/tag-sign.py does not exist (the sign-tag job's offline half): none of the 38 cases below can run"; echo "pass=$pass fail=$failn"; exit 1; fi
# ---- prepare ----
rm -f "$W/obj" "$W/digest"; rc=0; prep > "$W/prep.out" 2>&1 || rc=$?
if [ "$rc" = 0 ] && [ -s "$W/obj" ] && [ -s "$W/digest" ]; then ok "prepare writes the tag object and the digest"; else bad "prepare exit $rc: $(head -c 200 "$W/prep.out" 2> /dev/null)"; fi
python3 - "$W/obj" "$SHA" "$TAGGER" "$NOTES_TXT" <<'PY' && ok "the tag object is the four header lines, a blank line and the notes verbatim, with no signature" || bad "the tag object is not header + notes: $(head -c 300 "$W/obj" 2> /dev/null | tr '\n' '|')"
import sys
got = open(sys.argv[1], "rb").read()
want = "object %s\ntype commit\ntag v0.3.1\ntagger %s 1700000000 +0000\n\n%s" % tuple(sys.argv[2:5])
assert got == want.encode(), got
PY
git -C "$W/repo" mktag < "$W/obj" > /dev/null 2> "$W/mktag.err" && ok "git mktag accepts the prepared tag object (a well-formed tag of the commit)" || bad "git mktag refuses it: $(cat "$W/mktag.err")"
grep -Eqx '[0-9a-f]{64}' "$W/digest" && [ "$(wc -l < "$W/digest")" = 1 ] && ok "the digest file is one line of 64 lowercase hex characters" || bad "the digest file is not one sha256 hex line: $(head -c 100 "$W/digest")"
python3 - "$W/obj" "$W/digest" <<'PY' && ok "the digest is the sha256 of the SSHSIG signed-data blob (namespace git, reserved empty) over the object, for the hash algorithm the blob names" || bad "the digest is not sha256 of an SSHSIG signed-data blob over the object"
import hashlib, struct, sys
obj, want = open(sys.argv[1], "rb").read(), open(sys.argv[2]).read().strip()
s = lambda b: struct.pack(">I", len(b)) + b
cands = set()
for alg in ("sha256", "sha512"):
    blob = b"SSHSIG" + s(b"git") + s(b"") + s(alg.encode()) + s(hashlib.new(alg, obj).digest())
    cands.add(hashlib.sha256(blob).hexdigest())
assert want in cands, (want, cands)
PY
cp "$W/obj" "$W/obj1"; cp "$W/digest" "$W/digest1"; prep > /dev/null 2>&1 || true
cmp -s "$W/obj" "$W/obj1" && cmp -s "$W/digest" "$W/digest1" && ok "prepare is deterministic: the same inputs give the same object and digest" || bad "prepare differs between two runs"
rc=0; prep v0.3.1 "$SHA" "$W/notes.md" "$TAGGER" 1700000000 "$W/nest/a/obj" "$W/nest/b/digest" > "$W/nest.out" 2>&1 || rc=$?
{ [ "$rc" = 0 ] && cmp -s "$W/nest/a/obj" "$W/obj" && cmp -s "$W/nest/b/digest" "$W/digest"; } && ok "prepare creates the parent directory of --object and --digest when it does not exist (the workflow step runs no mkdir)" || bad "prepare into a not-yet-existing directory -> exit $rc: $(head -c 200 "$W/nest.out")"
printf '%s' "${NOTES_TXT/no change/other}" > "$W/notes2.md"
other=$(git -C "$W/repo" commit-tree -m x "$(git -C "$W/repo" rev-parse 'HEAD^{tree}')")
for v in "tag:v0.3.2" "commit:$other" "notes:$W/notes2.md" "tagger:fosterstack release <x@users.noreply.github.com>" "time:1700000001"; do
  k=${v%%:*}; val=${v#*:}; rm -f "$W/obj2" "$W/digest2"
  case "$k" in
    tag) prep "$val" "" "" "" "" "$W/obj2" "$W/digest2" ;; commit) prep v0.3.1 "$val" "" "" "" "$W/obj2" "$W/digest2" ;;
    notes) prep v0.3.1 "" "$val" "" "" "$W/obj2" "$W/digest2" ;; tagger) prep v0.3.1 "" "" "$val" "" "$W/obj2" "$W/digest2" ;;
    time) prep v0.3.1 "" "" "" "$val" "$W/obj2" "$W/digest2" ;;
  esac > /dev/null 2>&1 || true
  [ -s "$W/digest2" ] && ! cmp -s "$W/digest2" "$W/digest" && ok "the digest changes with the $k" || bad "the digest does not change with the $k"
done
# refusals: the release key signs patch tags only
for t in v0.3.0 v0.3.1-rc1 v1.0.0 v0.3 main "v0.3.1 " v0.3.01; do
  rm -f "$W/o3" "$W/d3"; rc=0; prep "$t" "" "" "" "" "$W/o3" "$W/d3" > /dev/null 2>&1 || rc=$?
  [ "$rc" != 0 ] && [ ! -e "$W/o3" ] && [ ! -e "$W/d3" ] && ok "prepare refuses the tag name '$t' (not vX.Y.Z with Z >= 1) and writes nothing" || bad "prepare accepted '$t' (exit $rc)"
done
rm -f "$W/o3" "$W/d3"; rc=0; prep v0.3.1 abc123 "" "" "" "$W/o3" "$W/d3" > /dev/null 2>&1 || rc=$?
[ "$rc" != 0 ] && [ ! -e "$W/o3" ] && ok "prepare refuses a commit that is not 40 hex characters" || bad "prepare accepted a short commit (exit $rc)"
# ---- assemble and the oracle: git verify-tag ----
kms_sign "$W/digest" "$W/sig"
rc=0; rm -f "$W/signed"; python3 "$TS" assemble --object "$W/obj" --signature "$W/sig" --signer-file "$W/signer" --out "$W/signed" > "$W/asm.out" 2>&1 || rc=$?
[ "$rc" = 0 ] && [ -s "$W/signed" ] && ok "assemble writes the signed tag object" || bad "assemble exit $rc: $(head -c 200 "$W/asm.out" 2> /dev/null)"
if verify "$W/signed" "$W/signer"; then ok "git verify-tag accepts the assembled tag against the one-line allowed-signers file ($(sed -n 's/.*Good/Good/p' <<< "$VOUT" | head -1 | cut -c1-70))"
else bad "git verify-tag refuses the assembled tag: $VOUT"; fi
grep -q 'with RSA key' <<< "${VOUT:-}" && ok "the signer is the RSA key" || bad "the verified signer is not an RSA key: ${VOUT:-}"
python3 - "$W/obj" "$W/signed" <<'PY' && ok "the signed object is the prepared object followed by exactly one SSH SIGNATURE block, last" || bad "the signed object is not object + one SSH SIGNATURE block"
import base64, re, sys
obj, signed = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
assert signed.startswith(obj)
tail = signed[len(obj):].decode()
m = re.fullmatch(r"-----BEGIN SSH SIGNATURE-----\n([A-Za-z0-9+/=\n]+)\n-----END SSH SIGNATURE-----\n", tail)
assert m, tail[:80]
assert signed.count(b"-----BEGIN ") == 1
PY
python3 - "$W/signed" <<'PY' && ok "the signature blob is SSHSIG version 1, namespace git, and the algorithm is rsa-sha2-256 (the KMS key signs RSASSA-PKCS1-v1_5 SHA-256)" || bad "the signature blob is not SSHSIG/git/rsa-sha2-256"
import base64, re, struct, sys
t = open(sys.argv[1], "rb").read().decode()
b = base64.b64decode("".join(re.search(r"-----BEGIN SSH SIGNATURE-----\n(.*)\n-----END SSH SIGNATURE-----", t, re.S).group(1).split()))
assert b[:6] == b"SSHSIG" and struct.unpack(">I", b[6:10])[0] == 1
def rd(o):
    n = struct.unpack(">I", b[o:o + 4])[0]; return b[o + 4:o + 4 + n], o + 4 + n
pk, o = rd(10); ns, o = rd(o); rs, o = rd(o); ha, o = rd(o); sg, o = rd(o)
assert ns == b"git" and rs == b"", (ns, rs)
assert ha in (b"sha256", b"sha512"), ha
n = struct.unpack(">I", sg[:4])[0]
assert sg[4:4 + n] == b"rsa-sha2-256", sg[4:4 + n]
n2 = struct.unpack(">I", pk[:4])[0]
assert pk[4:4 + n2] == b"ssh-rsa"
PY
# the binding: a changed message, another key, another signer file
sed 's/dependency or VEX maintenance only/changed after signing/' "$W/signed" > "$W/tampered"
verify "$W/tampered" "$W/signer" && bad "git verify-tag accepts a tag whose notes changed after signing" || ok "a tag whose notes changed after signing does not verify"
verify "$W/signed" "$W/signer-other" && bad "git verify-tag accepts the signature under another key" || ok "the signature does not verify under another RSA key"
rc=0; python3 "$TS" assemble --object "$W/obj" --signature "$W/sig" --signer-file "$W/signer-other" --out "$W/signed-other" > /dev/null 2>&1 || rc=$?
if [ "$rc" = 0 ]; then verify "$W/signed-other" "$W/signer-other" && bad "a signature made by one key verifies under another's key block" || ok "a signature assembled with another key's block does not verify"; else ok "assemble refuses a signature that does not match the key (exit $rc)"; fi
# assemble refusals
printf 'release@fosterstack ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA==\n' > "$W/signer-ed"; : > "$W/empty"
for c in "signer-ed:sig" "signer:empty" "nosuch:sig" "signer:nosuch"; do
  rm -f "$W/o4"; rc=0
  python3 "$TS" assemble --object "$W/obj" --signature "$W/${c#*:}" --signer-file "$W/${c%%:*}" --out "$W/o4" > /dev/null 2>&1 || rc=$?
  [ "$rc" != 0 ] && [ ! -e "$W/o4" ] && ok "assemble refuses (signer file $(echo "${c%%:*}"), signature $(echo "${c#*:}")) and writes nothing" || bad "assemble accepted signer=${c%%:*} signature=${c#*:} (exit $rc)"
done
# ---- the notes are read back from the signed tag (REQ-REL-009-AC8; R4): patch-decide tag-notes ----
verify "$W/signed" "$W/signer" > /dev/null 2>&1 || true
git -C "$W/repo" cat-file tag v0.3.1 > "$W/raw"
rc=0; python3 "$root/bin/patch-decide.py" tag-notes < "$W/raw" > "$W/n1.out" 2> "$W/n1.err" || rc=$?
{ [ "$rc" = 0 ] && [ "$(cat "$W/n1.out")" = "${NOTES_TXT%$'\n'}" ]; } && ok "patch-decide tag-notes reads the notes of the KMS-signed generated tag (heading, fixes, VEX), the signature dropped" || bad "patch-decide tag-notes -> exit $rc: $(head -c 200 "$W/n1.err") out: $(head -c 100 "$W/n1.out")"
sed 's/^tagger .*/tagger Someone <s@example.com> 1700000000 +0000/' "$W/raw" > "$W/raw-other"
rc=0; python3 "$root/bin/patch-decide.py" tag-notes < "$W/raw-other" > "$W/n3.out" 2> /dev/null || rc=$?
{ [ "$rc" = 1 ] && [ ! -s "$W/n3.out" ]; } && ok "patch-decide tag-notes: the same tag under another tagger carries no notes (exit 1)" || bad "patch-decide tag-notes with another tagger -> exit $rc"
# a refused form in the notes is refused (exit 2, the line named) even though the tag is genuinely signed: the notes are checked when they are read
printf '%s' "${NOTES_TXT/no change/-----BEGIN x}" > "$W/notes-bad.md"
prep v0.3.1 "" "$W/notes-bad.md" "" "" "$W/obj-bad" "$W/digest-bad" > /dev/null 2>&1 || true
if [ -s "$W/obj-bad" ]; then
  kms_sign "$W/digest-bad" "$W/sig-bad"; python3 "$TS" assemble --object "$W/obj-bad" --signature "$W/sig-bad" --signer-file "$W/signer" --out "$W/signed-bad" > /dev/null 2>&1 || true
  id=$(git -C "$W/repo" hash-object -t tag -w "$W/signed-bad" 2> /dev/null || echo none)
  if [ "$id" != none ]; then
    git -C "$W/repo" cat-file tag "$id" > "$W/raw-bad"; rc=0; python3 "$root/bin/patch-decide.py" tag-notes < "$W/raw-bad" > /dev/null 2> "$W/n5.err" || rc=$?
    { [ "$rc" = 2 ] && grep -q 'tag message:' "$W/n5.err"; } && ok "patch-decide tag-notes refuses a '-----BEGIN ' in the notes of a signed generated tag (exit 2, the line named)" || bad "tag-notes on a notes line holding BEGIN -> exit $rc: $(head -c 150 "$W/n5.err")"
  else bad "the tag with a BEGIN line in its notes could not be stored"; fi
else bad "prepare wrote no object for the notes holding a BEGIN line (the notes are decide's to check, not prepare's)"; fi
# ---- source admission's router sees an SSH signature (kind ssh), as for the owner ----
rc=0; python3 "$root/bin/admission-tag-signer.py" route --tag-object "$W/raw" > "$W/route.out" 2>&1 || rc=$?
[ "$rc" = 0 ] && [ "$(cut -d' ' -f1 "$W/route.out")" = ssh ] && ok "bin/admission-tag-signer.py routes the assembled tag to the ssh verifier" || bad "router -> exit $rc: $(cat "$W/route.out")"
echo "pass=$pass fail=$failn"
[ "$failn" = 0 ]
