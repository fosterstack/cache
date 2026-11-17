#!/usr/bin/env bash
# bin/rebuild-records-digests.sh  --  lists of the records Rebuild's jobs made (REQ-CHAIN-005-AC4); every list is compact, key-sorted JSON on standard output,
# keyed by the record-folder names the second call of Sign receives, each holding {file name: sha256:<hex>} for every file of the folder. The text leaves a job as a file the job uploads,
# or, for the assemble job's whole list, as a job output: channels the artifact names cannot reach. It builds nothing.
#   REBUILD_DIR RAPK_DIR...     the assemble job's whole list after its Witness step (witness-rebuild for REBUILD_DIR, witness-rapk-<runner> for each RAPK_DIR, <runner> the folder's own name)
#   --rapk RUNNER DIR OUTFILE  one apk leg's list after that leg's Witness step, written to OUTFILE: {"witness-rapk-<RUNNER>": {file: sha256}}
#   --check X86_FILE ARM_FILE   in the assemble job BEFORE its Witness step: each leg's uploaded file (the ubuntu-24.04 job's, then the ubuntu-24.04-arm job's)
#                               must equal the list recomputed from rec-rapk/<runner>; refuses on any difference, extra or missing file or folder, empty or invalid JSON
set -euo pipefail

emit() {
  # emit NAME DIR: one line per file of DIR, NAME TAB file TAB sha256
  local name="$1" dir="$2" n=0 f sum
  if [ ! -d "$dir" ] || [ -L "$dir" ]; then
    echo "rebuild-records-digests: not a plain folder: $dir" >&2
    return 1
  fi
  for f in "$dir"/* "$dir"/.[!.]* "$dir"/..?*; do
    if [ ! -e "$f" ] && [ ! -L "$f" ]; then
      continue     # a pattern that matched nothing stays literal: skip it (hidden files are files of the folder too, as for Sign's own listing)
    fi
    if [ ! -f "$f" ] || [ -L "$f" ]; then
      echo "rebuild-records-digests: not a regular file: $f" >&2
      return 1
    fi
    sum=$(openssl dgst -sha256 -r "$f" | cut -d' ' -f1)
    printf '%s\t%s\t%s\n' "$name" "$(basename "$f")" "$sum"
    n=1
  done
  if [ "$n" = 0 ]; then
    echo "rebuild-records-digests: no file in $dir" >&2
    return 1
  fi
}

to_json() {
  jq -S -c -R -n 'reduce (inputs | split("\t")) as $r ({}; .[$r[0]][$r[1]] = ("sha256:" + $r[2]))'
}

check_leg() {
  # check_leg RUNNER FILE: the leg's file must be exactly what the folder holds now
  local runner="$1" file="$2" got norm want
  if [ ! -f "$file" ] || [ -L "$file" ]; then
    echo "rebuild-records-digests: $runner: not a regular file: $file" >&2
    return 1
  fi
  got=$(cat "$file")
  if [ -z "$got" ]; then
    echo "rebuild-records-digests: $runner: the apk job's records file is empty" >&2
    return 1
  fi
  if ! norm=$(printf '%s' "$got" | jq -S -c 'if type == "object" then . else error("not an object") end'); then
    echo "rebuild-records-digests: $runner: the apk job's records output is not a JSON object" >&2
    return 1
  fi
  want=$(emit "witness-rapk-$runner" "rec-rapk/$runner" | to_json)
  if [ "$norm" != "$want" ]; then
    echo "rebuild-records-digests: $runner: the records changed since the apk job listed them (job output $norm, folder now $want)" >&2
    jq -n -r --argjson a "$norm" --argjson b "$want" 'def f: [to_entries[] | .key as $k | .value | to_entries[] | {key: ($k + "/" + .key), value: .value}] | from_entries; ($a | f) as $x | ($b | f) as $y | [$x, $y] | map(keys) | add | unique | map(select($x[.] != $y[.]))[]' 2> /dev/null | sed "s/^/rebuild-records-digests: $runner: differs: /" >&2 || true
    return 1
  fi
}

case "${1:-}" in
  --rapk)
    if [ "$#" -ne 4 ] || ! printf '%s' "$2" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9.-]*$'; then
      echo "rebuild-records-digests: usage: --rapk RUNNER DIR OUTFILE" >&2
      exit 2
    fi
    emit "witness-rapk-$2" "$3" | to_json > "$4"
    ;;
  --check)
    if [ "$#" -ne 3 ]; then
      echo "rebuild-records-digests: usage: --check X86_FILE ARM_FILE (exactly two files, each leg's uploaded list)" >&2
      exit 2
    fi
    check_leg ubuntu-24.04 "$2"
    check_leg ubuntu-24.04-arm "$3"
    ;;
  *)
    if [ "$#" -lt 2 ]; then
      echo "rebuild-records-digests: usage: REBUILD_DIR RAPK_DIR... | --rapk RUNNER DIR OUTFILE | --check X86_FILE ARM_FILE" >&2
      exit 2
    fi
    first=1
    {
      for d in "$@"; do
        base=$(basename "$d")
        name="witness-rapk-$base"
        if [ "$first" = 1 ]; then
          name="$base"
          first=0
        fi
        emit "$name" "$d"
      done
    } | to_json
    ;;
esac
