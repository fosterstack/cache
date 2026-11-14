#!/usr/bin/env bash
# bin/check-records-digests.sh RUNNER OUTFILE DIR...  --  a Check job's list of the records it made (REQ-REL-011-AC1; the contract of cache#606). It runs after the job's Witness steps and writes one
# compact, key-sorted JSON object in OUTFILE, keyed by RUNNER/<the record folder's own name> (ubuntu-24.04/witness-scanners, ...: both runners write the same three folders, so the runner
# is in the key and the two lists never collide), each holding {file name: sha256:<hex>} for every file of that folder. The text leaves the stage as an artifact of the job, a
# channel the artifact names cannot reach, and Sign refuses any record folder that differs from it. It builds nothing.
set -euo pipefail
if [ "$#" -lt 3 ]; then
  echo "check-records-digests: usage: RUNNER OUTFILE DIR..." >&2
  exit 2
fi
runner="$1"
out="$2"
shift 2
case "$runner" in ubuntu-24.04|ubuntu-24.04-arm) ;; *) echo "check-records-digests: unknown runner $runner" >&2; exit 2 ;; esac
{
  for d in "$@"; do
    if [ ! -d "$d" ] || [ -L "$d" ]; then
      echo "check-records-digests: not a plain folder: $d" >&2
      exit 1
    fi
    name="$runner/$(basename "$d")"
    n=0
    for f in "$d"/*; do
      if [ ! -f "$f" ] || [ -L "$f" ]; then
        echo "check-records-digests: not a regular file: $f" >&2
        exit 1
      fi
      sum=$(openssl dgst -sha256 -r "$f" | cut -d' ' -f1)
      printf '%s\t%s\t%s\n' "$name" "$(basename "$f")" "$sum"
      n=1
    done
    if [ "$n" = 0 ]; then
      echo "check-records-digests: no file in $d" >&2
      exit 1
    fi
  done
} | jq -S -c -R -n 'reduce (inputs | split("\t")) as $r ({}; .[$r[0]][$r[1]] = ("sha256:" + $r[2]))' > "$out"
