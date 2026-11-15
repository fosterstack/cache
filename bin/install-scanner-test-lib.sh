#!/usr/bin/env bash
# Sourced by the install-scanner tests, which set $work (a scratch folder) and $sut (the installer) first.
# The installer has no environment hooks: sutc ARCH [NAME=URL...] prints the path of a copy whose TEST-SUBST lines
# hold the given architecture and base addresses; a base not given points at an empty folder (no network).
sutc() {
  local f="$work/copy-$(printf '%s' "$*" | cksum | cut -d' ' -f1).sh"
  local o="file://$work/offline"
  python3 - "$sut" "$f" arch="$1" TRIVY_BASE="$o" GRYPE_BASE="$o" SYFT_BASE="$o" SNYK_BASE="$o" OSV_BASE="$o" \
    SBOMGEN_BASE="$o" SCOUT_BASE="$o" "${@:2}" <<'PY'
import re, sys
src, out = sys.argv[1:3]
subst = dict(a.split("=", 1) for a in sys.argv[3:])
seen, res = set(), []
for ln in open(src).read().split("\n"):
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=.*#\s*TEST-SUBST", ln)
    if m:
        if m.group(1) not in subst: sys.exit("no substitution given for %s" % m.group(1))
        seen.add(m.group(1)); res.append("%s=%s   # TEST-SUBST" % (m.group(1), subst[m.group(1)]))
    else:
        res.append(ln)
if seen != set(subst): sys.exit("substitutions with no TEST-SUBST line: %s" % sorted(set(subst) - seen))
open(out, "w").write("\n".join(res))
PY
  echo "$f"
}
