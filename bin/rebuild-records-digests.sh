#!/usr/bin/env bash
# bin/rebuild-records-digests.sh REBUILD_DIR RAPK_DIR...  --  the Rebuild assemble job's list of the records it made (REQ-CHAIN-005-AC4). It runs after the job's Witness step and prints
# one compact, key-sorted JSON object on standard output, keyed by the record-directory names the second call of Sign receives (witness-rebuild for REBUILD_DIR, witness-rapk-<runner>
# for each RAPK_DIR, <runner> being the folder's own name), each holding {file name: sha256:<hex>} for every file of that folder. The text leaves the stage as a job output, a
# channel the artifact names cannot reach, and Sign refuses any record folder that differs from it. It reads files and prints; it writes nothing and builds nothing.
set -euo pipefail
if [ "$#" -lt 2 ]; then
  echo "rebuild-records-digests: usage: REBUILD_DIR RAPK_DIR..." >&2
  exit 2
fi
first=1
{
  for d in "$@"; do
    if [ ! -d "$d" ] || [ -L "$d" ]; then
      echo "rebuild-records-digests: not a plain folder: $d" >&2
      exit 1
    fi
    base=$(basename "$d")
    name="witness-rapk-$base"
    if [ "$first" = 1 ]; then
      name="$base"
      first=0
    fi
    n=0
    for f in "$d"/*; do
      if [ ! -f "$f" ] || [ -L "$f" ]; then
        echo "rebuild-records-digests: not a regular file: $f" >&2
        exit 1
      fi
      sum=$(openssl dgst -sha256 -r "$f" | cut -d' ' -f1)
      printf '%s\t%s\t%s\n' "$name" "$(basename "$f")" "$sum"
      n=1
    done
    if [ "$n" = 0 ]; then
      echo "rebuild-records-digests: no file in $d" >&2
      exit 1
    fi
  done
} | jq -S -c -R -n 'reduce (inputs | split("\t")) as $r ({}; .[$r[0]][$r[1]] = ("sha256:" + $r[2]))'
