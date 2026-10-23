#!/usr/bin/env bash
# Pull the archive from GHCR by the digest committed in build/archive.json, into a new directory (REQ-ARCHIVE-001; rules 26, 27, 30, 44).
#
#   archive-pull.sh --pointer build/archive.json --out DIR [--digest sha256:<hex>]
#
# Runs before and outside the sealed call; melange and apko later see only the local directory (rules 38a, 38b). Nothing is pulled by tag,
# nothing falls back to another source. The files are staged beside DIR, checked against the pointer, and renamed to DIR only when
# every check passed: a failed or interrupted pull leaves nothing at DIR. An existing DIR is refused.
# Exit codes: 0 ok, 1 the artifact or a file did not match, 2 refused (bad input, a digest other than the committed one).
set -euo pipefail

# ---- fixed locations (REQ-ARCHIVE-001-AC9), see archive-push.sh

SELF=archive-pull.sh
die() { echo "$SELF: $1" >&2; exit "${2:-2}"; }


pointer= out= want= have=
while [ $# -gt 0 ]; do
  case $1 in
    --pointer) [ $# -ge 2 ] || die "usage: $SELF --pointer FILE --out DIR [--digest sha256:HEX]"; pointer=$2; shift 2;;
    --out) [ $# -ge 2 ] || die "usage: $SELF --pointer FILE --out DIR [--digest sha256:HEX]"; out=$2; shift 2;;
    --digest) [ $# -ge 2 ] || die "usage: $SELF --pointer FILE --out DIR [--digest sha256:HEX]"; want=$2; have=1; shift 2;;
    *) die "unknown argument: $1";;
  esac
done
[ -n "$pointer" ] && [ -n "$out" ] || die "usage: $SELF --pointer FILE --out DIR [--digest sha256:HEX]"
if [ -n "$have" ]; then
  case $want in
    sha256:*) hex=${want#sha256:}
      case $hex in *[!0-9a-f]*) die "--digest must be sha256:<64 lower-case hex>";; esac
      test "${#hex}" -eq 64 || die "--digest must be sha256:<64 lower-case hex>";;
    *) die "--digest must be sha256:<64 lower-case hex>";;
  esac
fi

art=$(/usr/bin/python3 -I -B bin/archive-verify.py artifact --pointer "$pointer") || exit $?
have=${art#*@}
if [ -n "$want" ] && [ "$want" != "$have" ]; then die "the digest $want is not the one committed in $pointer ($have): refusing" 2; fi

[ ! -e "$out" ] && [ ! -L "$out" ] || die "$out exists; the archive is pulled into a new directory"

tmp=$(/usr/bin/mktemp -d "$out.partial.XXXXXX")
cleanup() { /bin/rm -rf "$tmp"; }
trap cleanup EXIT

/usr/local/bin/crane pull --format oci "$art" "$tmp/layout" || die "crane pull of $art failed" 1
/usr/bin/python3 -I -B bin/archive-verify.py unpack --pointer "$pointer" --layout "$tmp/layout" --out "$out" || exit $?
