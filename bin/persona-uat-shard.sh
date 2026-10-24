#!/usr/bin/env bash
# bin/persona-uat-shard.sh: lets a long suite run ITSELF as parallel shards, and proves the shards together ran every case exactly once (REQ-CI-006). Sourced, never run.
#
#   . bin/persona-uat-shard.sh
#   shard_dispatch "$0" "$@"        first line of the suite: parent (forks the shards, proves the sum, exits), one shard, or the whole suite in one process
#   shard_section NAME FUNC...      a SECTION: a driver run and the checks that read what it left; its FUNCs (the parts of the section) run only in the shard that owns NAME
#   shard_tail_section NAME FUNC... a section that reads the case directories of EVERY shard (cross-case checks): runs once, after the shards, on their merged directories
#   shard_finish                    last line of the suite: the closing summary of this process
#
# The shards are the same file run again with PERSONA_SHARD=I/N: they run every cheap setup line, but only the sections assigned to them (committed weights, greedy
# by weight, the same answer in every process), each on its own ports (PERSONA_PORT_OFFSET = 100 x I) and its own work directory (PERSONA_WORK). The parent prints the
# cases, ONE closing line `persona-uat: S passed, F failed` counting the SUM, and only after bin/persona-uat-shard-sum.py has proved the shards ran exactly the cases
# of the committed manifest (PERSONA_SHARD_MANIFEST), each once. No more shards than cores; one process when there is one core or PERSONA_SHARDS=1.
# Environment: PERSONA_SHARDS (default 4), PERSONA_SHARD_MANIFEST, PERSONA_SHARD_WEIGHTS ("NAME SECONDS" per line; "NAME tail" marks a tail section),
# PERSONA_WRITE_MANIFEST=FILE (write the manifest from a green sharded run, for a human to commit), PERSONA_FAKE_CORES (tests).

_shard_lib_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

shard_cores() {
  local c=${PERSONA_FAKE_CORES:-}
  [ -n "$c" ] || c=$(nproc 2>/dev/null) || c=$(sysctl -n hw.ncpu 2>/dev/null) || c=1
  case $c in ''|*[!0-9]*) c=1 ;; esac
  [ "$c" -ge 1 ] || c=1
  echo "$c"
}

# shard_assign N NAME...: prints "SHARD NAME" per section in the order given. Greedy by weight (heaviest unit first to the least loaded shard, ties to the lowest). The weights file:
#   NAME SECONDS [shared]     a section's weight (a section without one counts as the median); "shared": it runs in EVERY shard (a driver run that many later sections read)
#                             but its cases are printed and counted only in its owner
#   NAME tail                 a tail section: not assigned, runs once after the shards (shard_tail_section)
#   @join A B ...             these sections are one unit: always the same shard (one reads what the other left)
# Deterministic: every process computes the same answer.
shard_assign() {
  local n=$1; shift
  awk -v n="$n" -v names="$*" -v wf="${PERSONA_SHARD_WEIGHTS:-/dev/null}" '
    function find(x) { while (par[x] != x) { par[x] = par[par[x]]; x = par[x] } return x }
    BEGIN {
      while ((getline line < wf) > 0) {
        c = split(line, f, " ")
        if (c == 0 || f[1] ~ /^#/) continue
        if (f[1] == "@join") { for (k = 2; k <= c; k++) { jn[++nj] = f[k]; jg[nj] = ngrp + 1 } ngrp++; jend[ngrp] = nj; continue }
        w[f[1]] = f[2]
      }
      cnt = split(names, nm, " ")
      m = 0
      for (i = 1; i <= cnt; i++) par[i] = i
      for (i = 1; i <= cnt; i++) if ((nm[i] in w) && w[nm[i]] != "tail") vals[++m] = w[nm[i]] + 0
      for (i = 1; i <= m; i++) for (j = i + 1; j <= m; j++) if (vals[j] < vals[i]) { t = vals[i]; vals[i] = vals[j]; vals[j] = t }
      med = (m > 0) ? vals[int((m + 1) / 2)] : 1
      for (i = 1; i <= cnt; i++) idx[nm[i]] = i
      for (g = 1; g <= ngrp; g++) {
        first = 0
        for (k = 1; k <= nj; k++) if (jg[k] == g && (jn[k] in idx)) { if (first == 0) first = idx[jn[k]]; else par[find(idx[jn[k]])] = find(first) }
      }
      for (i = 1; i <= cnt; i++) {
        istail[i] = ((nm[i] in w) && w[nm[i]] == "tail")
        wt[i] = (nm[i] in w) ? w[nm[i]] + 0 : med
      }
      for (i = 1; i <= cnt; i++) if (!istail[i]) { r = find(i); uw[r] += wt[i]; if (!(r in ufirst)) ufirst[r] = i }
      for (s = 0; s < n; s++) load[s] = 0
      nu = 0
      for (i = 1; i <= cnt; i++) if (!istail[i] && find(i) == i) ulist[++nu] = i
      for (k = 1; k <= nu; k++) {
        best = 0; bw = -1
        for (q = 1; q <= nu; q++) if (!(ulist[q] in done) && uw[ulist[q]] > bw) { best = ulist[q]; bw = uw[best] }
        if (best == 0) break
        done[best] = 1
        ls = 0
        for (s = 1; s < n; s++) if (load[s] < load[ls]) ls = s
        owner[best] = ls; load[ls] += uw[best]
      }
      for (i = 1; i <= cnt; i++) if (!istail[i]) print owner[find(i)], nm[i]
    }'
}

_shard_is_shared() { awk -v s="$1" '$1 == s && $3 == "shared" { f = 1 } END { exit !f }' "${PERSONA_SHARD_WEIGHTS:-/dev/null}"; }

_shard_sections() { # the manifest's section names, in order of first appearance
  awk -F'\t' '!/^#/ && NF >= 2 && !($1 in s) { s[$1] = 1; print $1 }' "${PERSONA_SHARD_MANIFEST:-/dev/null}"
}

SHARD_MODE=single SHARD_I="" SHARD_N=1 SHARD_SECS="" PERSONA_PORT_OFFSET=${PERSONA_PORT_OFFSET:-0}
_shard_map=""

shard_dispatch() {
  local self=$1; shift
  if [ -n "${PERSONA_SHARD:-}" ]; then          # a child: one shard or the tail
    SHARD_I=${PERSONA_SHARD%%/*}; SHARD_N=${PERSONA_SHARD##*/}
    if [ "$SHARD_I" = tail ]; then SHARD_MODE=tail; PERSONA_PORT_OFFSET=0
    else SHARD_MODE=shard; PERSONA_PORT_OFFSET=$((SHARD_I * 100)); fi
    export PERSONA_PORT_OFFSET
    if [ "$SHARD_I" = tail ]; then PERSONA_PORT_SLOT=$SHARD_N; else PERSONA_PORT_SLOT=$SHARD_I; fi   # the suite picks its fixture ports from this slot's own range
    export PERSONA_PORT_SLOT
    # shellcheck disable=SC2046
    _shard_map=$(shard_assign "$SHARD_N" $(_shard_sections))
    return 0
  fi
  local want=${PERSONA_SHARDS:-4} cores n
  cores=$(shard_cores)
  n=$want; [ "$n" -le "$cores" ] || n=$cores
  [ "$n" -le 4 ] || n=4                  # the fixture ports of a shard come from a range of its own: four shards and the tail fit
  if [ "$n" -le 1 ]; then SHARD_MODE=single; return 0; fi
  # the parent
  local d i rc=0 pids=() logs=() tails
  d=$(mktemp -d "${TMPDIR:-/tmp}/persona-shard.XXXXXX") || { echo "FAIL persona-uat: cannot make a temporary directory" >&2; exit 1; }
  trap '[ -z "${PERSONA_KEEP_DIR:-}" ] || { mkdir -p "$PERSONA_KEEP_DIR" && cp "$d"/*.log "$PERSONA_KEEP_DIR"/ 2>/dev/null; }; rm -rf "$d"' EXIT      # PERSONA_KEEP_DIR: keep the shard logs (a failing run is read from them)
  for ((i = 0; i < n; i++)); do
    PERSONA_SHARD="$i/$n" PERSONA_WORK="$d/w.$i" bash "$self" "$@" > "$d/shard.$i.log" 2>&1 < /dev/null &
    pids+=($!); logs+=("$d/shard.$i.log")
  done
  for ((i = 0; i < n; i++)); do wait "${pids[$i]}" || rc=1; done
  tails=$(awk '$2 == "tail" { print $1 }' "${PERSONA_SHARD_WEIGHTS:-/dev/null}")
  if [ -n "$tails" ]; then
    PERSONA_SHARD="tail/$n" PERSONA_WORK="$d/w.tail" PERSONA_SHARD_DIRS="$d" bash "$self" "$@" > "$d/tail.log" 2>&1 < /dev/null || rc=1
    logs+=("$d/tail.log")
  fi
  for f in "${logs[@]}"; do grep -E '^(ok   |FAIL |     why:)' "$f" || true; done
  for f in "${logs[@]}"; do if ! grep -q '^persona-uat: shard ' "$f"; then echo "persona-uat: $(basename "$f") has no shard line; its last lines:"; tail -n 12 "$f"; fi; done
  echo "persona-uat: shards=$n"
  if [ -n "${PERSONA_WRITE_MANIFEST:-}" ]; then
    python3 -I "$_shard_lib_dir/persona-uat-shard-sum.py" --write "$PERSONA_WRITE_MANIFEST" "${logs[@]}" || rc=1
    exit "$rc"
  fi
  python3 -I "$_shard_lib_dir/persona-uat-shard-sum.py" "${PERSONA_SHARD_MANIFEST:-/dev/null}" "${logs[@]}" || rc=1
  exit "$rc"
}

_shard_mine() { # NAME: is the section assigned to this process? (single: all)
  [ "$SHARD_MODE" = single ] && return 0
  [ "$SHARD_MODE" = shard ] || return 1
  [ "$(printf '%s\n' "$_shard_map" | awk -v s="$1" '$2 == s { print $1 }')" = "$SHARD_I" ]
}

shard_section() {
  local name=$1; shift
  if [ "$SHARD_MODE" != single ] && ! printf '%s\n' "$_shard_map" | awk -v s="$name" '$2 == s { f = 1 } END { exit !f }'; then
    [ "$SHARD_MODE" = shard ] && [ "$SHARD_I" = 0 ] && { echo "FAIL section $name is not in the manifest"; failn=$((${failn:-0} + 1)); }
    return 0
  fi
  SHARD_QUIET=""
  if ! _shard_mine "$name"; then
    # a shared section runs everywhere (the sections after it read what it leaves) but only its owner reports it
    if [ "$SHARD_MODE" = shard ] && _shard_is_shared "$name"; then SHARD_QUIET=1; else return 0; fi
  else
    SHARD_SECS="${SHARD_SECS:+$SHARD_SECS,}$name"
    echo "persona-uat: section $name"
  fi
  local t0=$SECONDS f
  for f in "$@"; do "$f"; done          # the parts of the section, in file order (the function definitions between them stay at top level)
  SHARD_QUIET=""
  [ "$SHARD_MODE" = single ] || echo "persona-uat: section $name took $((SECONDS - t0))s" >&2
}

shard_tail_section() {
  local name=$1 d e f; shift
  [ "$SHARD_MODE" = single ] || [ "$SHARD_MODE" = tail ] || return 0
  if [ "$SHARD_MODE" = tail ] && [ -n "${PERSONA_SHARD_DIRS:-}" ]; then   # the case directories of every shard, side by side
    for d in "$PERSONA_SHARD_DIRS"/w.[0-9]*; do
      [ -d "$d" ] || continue
      for e in "$d"/*; do [ -e "${work:?}/$(basename "$e")" ] || ln -s "$e" "$work/$(basename "$e")"; done
    done
  fi
  SHARD_SECS="${SHARD_SECS:+$SHARD_SECS,}$name"
  echo "persona-uat: section $name"
  for f in "$@"; do "$f"; done
}

shard_finish() {
  case $SHARD_MODE in
    single) echo "persona-uat: ${pass:-0} passed, ${failn:-0} failed" ;;
    *) echo "persona-uat: shard $([ "$SHARD_MODE" = tail ] && echo tail || echo "$SHARD_I/$SHARD_N") sections=$SHARD_SECS"
       echo "persona-uat: ${pass:-0} passed, ${failn:-0} failed" ;;
  esac
  [ "${failn:-0}" -eq 0 ]
}
