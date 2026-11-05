#!/usr/bin/env bash
# The VM wall probe, remount-write wall (REQ-CHAIN-004-AC19). Runs the hostile recipe build/probe/vm-remount.yaml.tmpl
# through the melange it is given and judges only the HOST side: two canary files keep their sha256, and nothing
# appears beside the workspace folder. The recipe cannot report anything; the exit code is the verdict.
# Exit 0: only the workspace changed. 4: not held. 1: probe error or no evidence (never a pass). 2: refused, bad arguments.
# Usage: bin/vm-sandbox-probe.sh --melange <melange> --workdir <new folder>
# UNVERIFIED until the first real run: the melange arguments below (runner and workspace flags).
set -uo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
melange="" workdir=""
while [ $# -gt 0 ]; do
  case "$1" in
    --melange) melange=${2-}; shift 2 ;;
    --workdir) workdir=${2-}; shift 2 ;;
    *) echo "vm-sandbox-probe: unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$melange" ] || { echo "vm-sandbox-probe: --melange is required" >&2; exit 2; }
[ -n "$workdir" ] || { echo "vm-sandbox-probe: --workdir is required" >&2; exit 2; }
[ ! -e "$workdir" ] || { echo "vm-sandbox-probe: --workdir must not exist yet: $workdir" >&2; exit 2; }

mkdir -p "$workdir/workspace" "$workdir/checkout" || exit 1
export WORKSPACE_DIR="$workdir/workspace"
export OUTSIDE_CANARY="$workdir/outside-canary"
export INSIDE_CANARY="$workdir/checkout/canary"
echo "canary outside the workspace" > "$OUTSIDE_CANARY" || exit 1
echo "canary inside the checkout copy" > "$INSIDE_CANARY" || exit 1
render=$(mktemp -d) || exit 1
cleanup() { chmod -R u+rwX "$workdir" 2>/dev/null; rm -rf "$render"; }
trap cleanup EXIT

sed -e 's|@BUSYBOX@|busybox|' -e "s|@CANARY_OUTSIDE@|$OUTSIDE_CANARY|" \
  "$here/build/probe/vm-remount.yaml.tmpl" > "$render/probe.yaml" || exit 1

hash_of() { sha256sum < "$1" 2>/dev/null | cut -d' ' -f1; }
outside_before=$(hash_of "$OUTSIDE_CANARY"); inside_before=$(hash_of "$INSIDE_CANARY")
[ -n "$outside_before" ] && [ -n "$inside_before" ] || { echo "vm-sandbox-probe: cannot read a canary before the run" >&2; exit 1; }
tree_before=$(find "$workdir" -path "$WORKSPACE_DIR" -prune -o ! -path "$OUTSIDE_CANARY" ! -path "$INSIDE_CANARY" -print | sort)

"$melange" build "$render/probe.yaml" --runner qemu --workspace-dir "$WORKSPACE_DIR" > "$render/melange.log" 2>&1
rc=$?
if [ "$rc" != 0 ]; then
  echo "vm-sandbox-probe: melange failed (exit $rc), no verdict" >&2; tail -5 "$render/melange.log" >&2; exit 1
fi

not_held=0 no_evidence=0
if [ ! -d "$WORKSPACE_DIR" ] || [ ! -r "$WORKSPACE_DIR" ] || [ ! -x "$WORKSPACE_DIR" ]; then
  echo "vm-sandbox-probe: the workspace folder is gone or unreadable" >&2; no_evidence=1
fi
outside_after=$(hash_of "$OUTSIDE_CANARY"); inside_after=$(hash_of "$INSIDE_CANARY")
for c in outside inside; do
  b=${c}_before a=${c}_after
  if [ -z "${!a}" ]; then echo "vm-sandbox-probe: the $c canary cannot be read" >&2; no_evidence=1
  elif [ "${!a}" != "${!b}" ]; then echo "vm-sandbox-probe: the $c canary changed" >&2; not_held=1; fi
done
tree_after=$(find "$workdir" -path "$WORKSPACE_DIR" -prune -o ! -path "$OUTSIDE_CANARY" ! -path "$INSIDE_CANARY" -print 2>/dev/null | sort)
echo "vm-sandbox-probe: outside canary sha256:$outside_before -> sha256:${outside_after:-unreadable}"
echo "vm-sandbox-probe: inside canary sha256:$inside_before -> sha256:${inside_after:-unreadable}"
echo "vm-sandbox-probe: workspace listing: $(ls -A "$WORKSPACE_DIR" 2>&1 | tr '\n' ' ')"
# the positive control: the hostile step must have left its file in the workspace, or the wall was never tested
if [ -z "$(find "$WORKSPACE_DIR" -name vm-probe-written 2>/dev/null | head -n 1)" ]; then
  echo "vm-sandbox-probe: no evidence the hostile step ran (vm-probe-written is not in the workspace)" >&2; no_evidence=1
fi
if [ "$tree_before" != "$tree_after" ]; then
  echo "vm-sandbox-probe: something appeared or went beside the workspace folder" >&2; not_held=1
fi
if [ "$not_held" = 1 ]; then exit 4; fi
if [ "$no_evidence" = 1 ]; then exit 1; fi
echo "vm-sandbox-probe: held (only the workspace changed)"
