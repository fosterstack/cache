#!/usr/bin/env bash
# Enforce ZERO uncovered eligible statements per module (test-strategy §6).
# Merges the -coverpkg profile's duplicate blocks by max count (a block
# covered in any test binary is covered), applies committed exclusions,
# and fails if any eligible statement is uncovered.
set -euo pipefail
profile="$1"; label="$2"
excl=.github/policy/coverage-exclusions.txt
prefixes=$(grep -vE '^\s*(#|$)' "$excl" 2>/dev/null | awk '{print $1}' || true)
awk -v label="$label" -v prefixes="$prefixes" '
  NR==1 { next }                       # mode line
  {
    key=$1; n[key]=$2; if ($3+0 > c[key]+0) c[key]=$3
  }
  END {
    split(prefixes, px, "\n")
    total=0; covered=0; uncov=0; uncovlines=""
    for (k in c) {
      excluded=0
      for (i in px) if (px[i] != "" && index(k, px[i])==1) excluded=1
      if (excluded) continue
      total += n[k]
      if (c[k]+0 > 0) covered += n[k]
      else { uncov += n[k]; uncovlines = uncovlines "\n    " k }
    }
    pct = (total>0) ? 100.0*covered/total : 100.0
    printf "%s: %d/%d statements covered (%.2f%%), %d uncovered\n", label, covered, total, pct, uncov
    if (uncov > 0) { printf "::error::%s has %d uncovered eligible statements:%s\n", label, uncov, uncovlines; exit 1 }
  }
' "$profile"
