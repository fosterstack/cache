#!/usr/bin/env bash
# proves: REQ-SUP-001-AC34, REQ-SUP-001-AC31
# bin/verify-go.sh <archive> <archive.asc> checks a Go toolchain archive against Google's Linux packages signing key, pinned by fingerprint.
# Proved offline with throwaway gpg keys: the script reads the key from VERIFY_GO_KEYFILE and the pinned fingerprint may be overridden by VERIFY_GO_FPR.
# Every failing case must exit non-zero and say nothing that claims the archive is verified.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
script="$here/verify-go.sh"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { failn=$((failn+1)); echo "FAIL $1"; }
PINNED=EB4C1BFD4F042F6DDDCCEC917721F63BD38B4796

if [ -f "$script" ]; then ok "bin/verify-go.sh exists"; else bad "bin/verify-go.sh exists"; fi

# the default fingerprint is the pinned one, written out in the script
if [ -f "$script" ] && grep -q "$PINNED" "$script"; then ok "the script carries the pinned fingerprint text"; else bad "the script carries the pinned fingerprint text"; fi
if [ -f "$script" ] && ! grep -E '[0-9A-F]{40}' "$script" | grep -qv "$PINNED"; then ok "no other 40-hex fingerprint in the script"; else bad "no other 40-hex fingerprint in the script"; fi

# a curl that fails and records, so a run that reaches for the network is seen
mkdir -p "$work/shim"
printf '#!/bin/sh\necho "$@" >>"%s/curl.log"\nexit 7\n' "$work" >"$work/shim/curl"; chmod +x "$work/shim/curl"

G="$work/gnupg"; mkdir -m 700 "$G"
gen() { # <name> [faked time] [expire]
  local args=(--batch --passphrase '' --quick-gen-key "$1 <$1@example.invalid>" ed25519 sign "${3:-never}")
  [ -n "${2:-}" ] && args=(--faked-system-time "$2" "${args[@]}")
  GNUPGHOME=$G gpg "${args[@]}" >/dev/null 2>&1
}
fpr() { GNUPGHOME=$G gpg --with-colons --list-keys "$1@example.invalid" 2>/dev/null | awk -F: '$1=="fpr"{print $10; exit}'; }
gen good; gen other
gen expiredkey 20200101T000000 1d
gen revoked
gen expsig
F_GOOD=$(fpr good); F_OTHER=$(fpr other); F_EXPK=$(fpr expiredkey); F_REV=$(fpr revoked); F_EXPSIG=$(fpr expsig)
# revoke "revoked" and keep the revocation in the keyring
printf 'y\n0\n\ny\n' | GNUPGHOME=$G gpg --yes --no-tty --command-fd 0 --output "$work/rev.asc" --gen-revoke "$F_REV" >/dev/null 2>&1 || true
GNUPGHOME=$G gpg --batch --import "$work/rev.asc" >/dev/null 2>&1 || true
keyfile() { GNUPGHOME=$G gpg --armor --export "$@" >"$work/keys.asc"; }
keyfile "$F_GOOD" "$F_OTHER" "$F_EXPK" "$F_REV" "$F_EXPSIG"

printf 'go archive bytes\n' >"$work/go.tgz"
sign() { # <fpr> <out> [extra gpg args...]
  local f=$1 out=$2; shift 2
  GNUPGHOME=$G gpg --batch --yes --passphrase '' "$@" --local-user "$f" --armor --detach-sign --output "$out" "$work/go.tgz" >/dev/null 2>&1 || true
}
sign "$F_GOOD" "$work/good.asc"
sign "$F_OTHER" "$work/other.asc"
sign "$F_EXPK" "$work/expk.asc" --faked-system-time 20200101T120000
sign "$F_REV" "$work/rev.sig.asc"
sign "$F_EXPSIG" "$work/expsig.asc" --faked-system-time 20200101T000000 --default-sig-expire 1d
: >"$work/empty.asc"

# run <fpr> <archive> <asc>: output in $work/out, exit code in $rc; a clean empty keyring for the script, so only the keyfile can vouch
run() {
  local f=$1; shift; mkdir -p "$work/clean" && chmod 700 "$work/clean"; : >"$work/curl.log"
  rc=0; env -i PATH="$work/shim:/usr/bin:/bin" HOME="$work" GNUPGHOME="$work/clean" VERIFY_GO_KEYFILE="$work/keys.asc" VERIFY_GO_FPR="$f" \
    bash "$script" "$@" >"$work/out" 2>&1 || rc=$?
}
says_verified() { sed -E 's/(not|un|NOT|failed to be) ?verified//Ig' "$work/out" >"$work/out2"; grep -qi 'verified' "$work/out2"; }
must_fail() { # <case> <fpr> <archive> <asc>
  local c=$1; shift
  if [ ! -f "$script" ]; then bad "$c (no script)"; return; fi
  run "$@"
  if [ "$rc" -eq 0 ]; then bad "$c: exit 0"; return; fi
  if [ "$rc" -eq 126 ] || [ "$rc" -eq 127 ]; then bad "$c: script could not run (exit $rc)"; return; fi
  if says_verified; then bad "$c: output says verified"; return; fi
  ok "$c"
}

# good: a good signature by the key whose fingerprint is the pinned one
if [ -f "$script" ]; then
  run "$F_GOOD" "$work/go.tgz" "$work/good.asc"
  if [ "$rc" -eq 0 ]; then ok "good signature by the pinned key passes"; else bad "good signature by the pinned key passes (exit $rc: $(head -c 300 "$work/out"))"; fi
  if [ ! -s "$work/curl.log" ]; then ok "the keyfile case does not touch the network"; else bad "the keyfile case does not touch the network"; fi
else bad "good signature by the pinned key passes (no script)"; fi

must_fail "wrong signer (valid signature by another key) fails" "$F_GOOD" "$work/go.tgz" "$work/other.asc"
must_fail "a revoked key fails (REVKEYSIG)" "$F_REV" "$work/go.tgz" "$work/rev.sig.asc"
must_fail "an expired key fails (EXPKEYSIG)" "$F_EXPK" "$work/go.tgz" "$work/expk.asc"
must_fail "an expired signature fails (EXPSIG)" "$F_EXPSIG" "$work/go.tgz" "$work/expsig.asc"
printf 'go archive bytes, changed\n' >"$work/tampered.tgz"
must_fail "a tampered archive fails" "$F_GOOD" "$work/tampered.tgz" "$work/good.asc"
must_fail "a missing .asc fails" "$F_GOOD" "$work/go.tgz" "$work/absent.asc"
must_fail "an empty .asc fails" "$F_GOOD" "$work/go.tgz" "$work/empty.asc"
must_fail "a missing archive fails" "$F_GOOD" "$work/absent.tgz" "$work/good.asc"
# the pinned default is not a throwaway key: with no override, the throwaway good signature must fail
if [ -f "$script" ]; then
  rc=0; env -i PATH="$work/shim:/usr/bin:/bin" HOME="$work" GNUPGHOME="$work/clean" VERIFY_GO_KEYFILE="$work/keys.asc" bash "$script" "$work/go.tgz" "$work/good.asc" >"$work/out" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ] && [ "$rc" -lt 126 ] && ! says_verified; then ok "without the override the pinned default rejects a throwaway key"; else bad "without the override the pinned default rejects a throwaway key"; fi
else bad "without the override the pinned default rejects a throwaway key (no script)"; fi

echo "$pass passed, $failn failed"
[ "$failn" -eq 0 ]
