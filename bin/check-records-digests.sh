#!/usr/bin/env bash
# bin/check-records-digests.sh DIR...  --  a Check job's list of the records it made (REQ-REL-011-AC1; the contract of cache#606). It runs after the job's Witness steps and prints one
# compact, key-sorted JSON object on standard output, keyed by the record-directory names the third call of Sign receives (the folder's own name: witness-scanners, witness-acceptance and
# witness-runtime for the check job, witness-arm64 for check-arm64), each holding {file name: sha256:<hex>} for every file of that folder. The text leaves the stage as a job output, a
# channel the artifact names cannot reach, and Sign refuses any record folder that differs from it. It reads files and prints; it writes nothing and builds nothing.
set -euo pipefail
if [ "$#" -lt 1 ]; then
  echo "check-records-digests: usage: DIR..." >&2
  exit 2
fi
{
  for d in "$@"; do
    if [ ! -d "$d" ] || [ -L "$d" ]; then
      echo "check-records-digests: not a plain folder: $d" >&2
      exit 1
    fi
    name=$(basename "$d")
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
} | jq -S -c -R -n 'reduce (inputs | split("\t")) as $r ({}; .[$r[0]][$r[1]] = ("sha256:" + $r[2]))'
