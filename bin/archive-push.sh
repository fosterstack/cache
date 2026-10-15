#!/usr/bin/env bash
# Push the archive directory to GHCR as one OCI artifact, by digest (REQ-ARCHIVE-001; rules 27, 29, 44).
#
#   archive-push.sh --dir DIR
#
# One layer per regular file, annotated with name, version and sha256. Prints the artifact digest (sha256:<hex>) and nothing else on stdout.
# This is the only writer of the archive store and only the refresh job calls it, with the workflow's own credential (packages: write),
# which crane finds itself: this script reads no token and no variable of the caller.
# Exit codes: 0 ok, 1 the push failed or crane reported another digest than the one computed, 2 refused (bad input).
set -euo pipefail

# ---- fixed locations (REQ-ARCHIVE-001-AC9): no tool is resolved through the caller's search path, and there is no test hook in this file:
# bin/archive-test.sh runs a COPY in which exactly the lines ending in TEST-SUBST are replaced, and checks the copy differs in no other line.
PY3=/usr/bin/python3            # TEST-SUBST
CRANE=/usr/local/bin/crane      # TEST-SUBST (the version pinned in stage-promote.yml)
MKTEMP=/usr/bin/mktemp          # TEST-SUBST
RM=/bin/rm                      # TEST-SUBST

SELF=archive-push.sh
die() { echo "$SELF: $1" >&2; exit "${2:-2}"; }


dir=
while [ $# -gt 0 ]; do
  case $1 in
    --dir) [ $# -ge 2 ] || die "usage: $SELF --dir DIR"; dir=$2; shift 2;;
    *) die "unknown argument: $1";;
  esac
done
[ -n "$dir" ] || die "usage: $SELF --dir DIR"
[ -d "$dir" ] || die "--dir must be an existing directory"

tmp=$("$MKTEMP" -d)
cleanup() { "$RM" -rf "$tmp"; }
trap cleanup EXIT

ref=$("$PY3" -I -B bin/archive-verify.py pack --dir "$dir" --layout "$tmp/layout") || exit $?   # TEST-SUBST
digest=${ref#*@}

out=$("$CRANE" push "$tmp/layout" "$ref") || die "crane push failed" 1
[ "$out" = "$ref" ] || die "the registry reported $out, not the digest computed from the layout ($ref)" 1
echo "$digest"
