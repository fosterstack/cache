#!/usr/bin/env bash
# The sandbox wall probe of the dry run (sandboxed-build rules 3, 5 and 6). It builds six test-only recipes (build/probe/*.yaml.tmpl) through
# the same sealed melange call as the apk build and reads only melange's exit status, never the recipe's output:
#   control       a harmless step with every tool the attempts use; it must exit 0, else the probe stops (exit 1) and judges nothing
#   read-record   cat the host path of this job's Witness record        write-record   append to it (the probe also compares its sha256)
#   read-keydir   cat a file of a stand-in key folder made here          read-token     the sandbox's environment grepped for the runner's token names
#   network       an HTTP fetch of a literal address (no name lookup)    then the net probe in a namespace made with unshare -n: 101 = sealed
# melange exit 0 on an attempt means the wall is open (exit 4). Any other exit means the wall held, but only because the control passed.
# Exit 0: every wall held. 1: probe error (a failed control, melange not run, exit 126 or 127). 2: refused (a missing input, or the sealed
# call judge refused the call). 4: a wall is open. Nothing is signed, uploaded or published; the temporary folders are removed on exit.
set -euo pipefail

# Fixed locations: a call never resolves a program through the caller's search list. The offline test runs a COPY in
# which exactly the lines ending in TEST-SUBST are replaced, and checks that the copy differs from this file in no other line.
PY3=/usr/bin/python3            # TEST-SUBST
SUDO=/usr/bin/sudo              # TEST-SUBST
UNSHARE=/usr/bin/unshare        # TEST-SUBST
MELANGE=/usr/local/bin/melange  # TEST-SUBST (the chain installs it there)
SHA256SUM=/usr/bin/sha256sum    # TEST-SUBST
ENVBIN=/usr/bin/env             # TEST-SUBST
SEALED_ENV=build/sealed-env.json  # TEST-SUBST
REPO=$PWD/archive               # TEST-SUBST (the archive the apk build reads)
KEYRING=$PWD/archive/keys/wolfi-signing.rsa.pub  # TEST-SUBST
RECORD=$PWD/witness-apk/apk-collection.local.json  # TEST-SUBST (this job's Witness record)
LOCK=build/locks/melange.lock   # TEST-SUBST

[ -f bin/chain-sandbox-probe.sh ] && [ -f bin/build-apk-helper.py ] && [ -f build/sealed-env.json ] \
  || { echo "chain-sandbox-probe.sh: run it from the repository root" >&2; exit 2; }
[ -f "$RECORD" ] || { echo "chain-sandbox-probe.sh: the Witness record $RECORD is missing" >&2; exit 2; }
arch=$(uname -m)
[ "$arch" = x86_64 ] || [ "$arch" = aarch64 ] || { echo "chain-sandbox-probe.sh: unsupported architecture $arch" >&2; exit 2; }
busybox=$(grep -m 1 '^busybox=' "$LOCK") || { echo "chain-sandbox-probe.sh: $LOCK has no busybox row" >&2; exit 2; }

umask 077
tmp=$(mktemp -d)
kd=$(mktemp -d "${RUNNER_TEMP:?}/probe-keydir.XXXXXX")
trap 'rm -rf "$tmp" "$kd"' EXIT HUP INT TERM
printf 'dummy, not a key\n' >"$kd/dummy"
mkdir -p "$tmp/recipes" "$tmp/cache"
for w in control read-record write-record read-keydir read-token network; do
  sed -e "s|@BUSYBOX@|$busybox|" -e "s|@RECORD@|$RECORD|" -e "s|@KEYDIR@|$kd|" "build/probe/$w.yaml.tmpl" >"$tmp/recipes/probe-$w.yaml"
done

# The sealed environment is the committed file's items; its one name taken from the environment gets a fixed value: nothing built here is kept.
export SOURCE_DATE_EPOCH=0
mapfile -d '' -t sealed < <("$PY3" -I -B bin/build-apk-helper.py sealed-env "$SEALED_ENV")
set -- "${sealed[@]}"
[ "$#" -ge 4 ] || { echo "chain-sandbox-probe.sh: the sealed environment could not be made" >&2; exit 2; }

RC=0
run_wall() { # run_wall NAME: sets RC to the exit status of one sealed melange call on that recipe
  local call why
  call=("$ENVBIN" -i "${sealed[@]}" "$UNSHARE" -n "$MELANGE" build "probe-$1.yaml" --arch "$arch" --runner bubblewrap --namespace fosterstack
    --keyring-append "$KEYRING" --repository-append "$REPO" --cache-dir "$tmp/cache" --source-dir "$PWD" --out-dir "$tmp/out-$1")
  why=$("$PY3" -I -B bin/build-apk-helper.py sealed-call --sealed-env "$SEALED_ENV" "${call[@]}" 2>&1) \
    || { echo "chain-sandbox-probe.sh: refusing the melange call: $why" >&2; exit 2; }
  RC=0
  (cd "$tmp/recipes" && "$SUDO" "${call[@]}" >"$tmp/$1.log" 2>&1) || RC=$?
}

run_wall control
cat "$tmp/control.log"
[ "$RC" = 0 ] || { echo "probe error: the control recipe exited $RC, so no wall is judged" >&2; exit 1; }
before=$("$SHA256SUM" "$RECORD" | cut -d' ' -f1)
open=0
for w in read-record write-record read-keydir read-token network; do
  run_wall "$w"
  [ "$RC" != 126 ] && [ "$RC" != 127 ] || { echo "probe error: melange did not run for $w (exit $RC)" >&2; exit 1; }
  if [ "$RC" = 0 ]; then echo "wall open: $w (the melange build passed, so the attempt worked)"; open=1; else echo "wall held: $w (melange exit $RC)"; fi
done
after=$("$SHA256SUM" "$RECORD" | cut -d' ' -f1)
[ "$before" = "$after" ] || { echo "wall open: write-record (the record's sha256 changed)"; open=1; }
nrc=0
"$SUDO" "$UNSHARE" -n "$PY3" -I -B bin/net-probe.py >/dev/null 2>&1 || nrc=$?
[ "$nrc" = 101 ] || { echo "wall open: network (net-probe exit $nrc in a namespace made with unshare -n; 101 is sealed)"; open=1; }
[ "$open" = 0 ] || exit 4
echo "all walls held"
