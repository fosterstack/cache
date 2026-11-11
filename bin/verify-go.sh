#!/usr/bin/env bash
# Go toolchain signature check (REQ-SUP-001-AC34): the archive is signed by Google's Linux packages key, pinned by fingerprint.
#   verify-go.sh ARCHIVE ARCHIVE.asc
# VERIFY_GO_KEYFILE (a key file) and VERIFY_GO_FPR exist for the offline tests; the defaults are the real key and fingerprint.
set -euo pipefail

archive=$1
sig=$2
fpr=${VERIFY_GO_FPR:-EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796}
key_url=https://dl.google.com/linux/linux_signing_key.pub

[ -s "$archive" ] || { echo "verify-go.sh: no archive $archive" >&2; exit 1; }
[ -s "$sig" ] || { echo "verify-go.sh: no signature $sig" >&2; exit 1; }

work=$(mktemp -d)
trap 'gpgconf --homedir "$work" --kill gpg-agent 2>/dev/null || true; rm -rf -- "$work"' EXIT
export GNUPGHOME=$work

if [ -n "${VERIFY_GO_KEYFILE:-}" ]; then
  cp -- "$VERIFY_GO_KEYFILE" "$work/key.asc"
else
  curl -q -fsSL -g --proto =https --tlsv1.2 -o "$work/key.asc" "$key_url"
fi
gpg --batch --quiet --import "$work/key.asc"
keys=$(gpg --batch --with-colons --fingerprint)
grep -qx "fpr:::::::::$fpr:" <<<"$keys" || { echo "verify-go.sh: the key is not $fpr" >&2; exit 1; }

# the status lines decide, not gpg's exit code; VALIDSIG ends with the primary fingerprint, whichever subkey signed
status=$(gpg --batch --status-fd 1 --verify "$sig" "$archive" 2>/dev/null || true)
if grep -q '^\[GNUPG:\] GOODSIG ' <<<"$status" && grep -Eq "^\[GNUPG:\] VALIDSIG .* $fpr\$" <<<"$status" \
  && ! grep -Eq '^\[GNUPG:\] (REVKEYSIG|EXPKEYSIG|EXPSIG) ' <<<"$status"; then
  echo "verify-go.sh: $archive is signed by $fpr"
else
  echo "verify-go.sh: $archive is not signed by $fpr" >&2
  exit 1
fi
