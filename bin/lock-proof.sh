#!/usr/bin/env bash
# The lock method proof (v0.3.0 rule 36): assembly must FAIL, for the right reason, when the archive or the config is wrong; and it must SUCCEED
# on the untouched inputs, otherwise a script that always fails would "prove" everything.
#
#   lock-proof.sh --out DIR --archive DIR -- <assemble-image.sh arguments>
#
# The arguments after `--` are passed to the assembly script as they are (--variant, --version, --melange-repo, --keyring-dir); this script
# supplies --archive and --out. The assembly uses the committed config, base lock and records of the variant: neither this script nor the
# assembler has an option for them or a test hook (REQ-IMAGE-001-AC10, AC12). Every assembly runs from a throwaway copy of the repository root
# (bin/ linked, build/ copied), so the live-packages case changes the config in its own copy and the real files are never modified. The
# record holds the sha256 of the config, the base lock, the index record and the key record that were proved against.
#   0. positive control: the untouched archive and config must assemble (exit 0). If not, the proof fails (exit 1, "positive control").
#   Then, on throwaway copies, the assembly must exit exactly 2 (the named refusal) AND say why:
#   missing-package   one package of the BASE LOCK deleted (the first by name)          -> the message names that apk
#   missing-index     that package's architecture loses its APKINDEX.tar.gz              -> the message names APKINDEX
#   tampered-package  one byte inside that apk changed                                   -> the message names that apk and "does not match"
#   live-packages     the config names a live Wolfi address instead of the archive       -> the message names a live repository
# OUT/lock-proof.json records the positive control, the assembly script (path and sha256), and for each case the exit code and the reason line.
# The real archive and config are never modified.
# Exit codes: 0 the control passed and all four cases failed as required | 1 the control failed, or a case did not fail, failed with another exit
#   code, or failed for another reason | 2 refused (bad arguments).
set -euo pipefail

# every tool is called by a fixed absolute path held in a variable (REQ-IMAGE-001-AC12); the tests substitute exactly these lines
HOST_OS=${BASH_VERSINFO[5]}          # TEST-SUBST (the running bash's own build host, read-only and not importable from the environment: no tool, no caller input)
PY3=/usr/bin/python3                 # TEST-SUBST
SUDO=/usr/bin/sudo                   # TEST-SUBST
BASHBIN=/bin/bash                    # TEST-SUBST
case ${BASH_SOURCE[0]} in */*) here_=${BASH_SOURCE[0]%/*};; *) here_=.;; esac   # the script's own directory without running dirname
here=$(cd "$here_" && pwd)
die() { echo "lock-proof.sh: $1" >&2; exit "${2:-2}"; }

[[ $HOST_OS == *linux* ]] || die "refusing to run on $HOST_OS: this script uses sudo, unshare and the sealed build tools, which run on Linux only (inside a Linux container or on a GitHub runner), never on the Mac itself" 2
# the chain runs everything from the repository root, and the drivers it calls refuse anywhere else (exit 2): run it as  bash bin/lock-proof.sh ...  from there
[ "$(pwd -P)" = "$(cd "$here/.." && pwd -P)" ] || die "usage: run bin/lock-proof.sh from the repository root ($(cd "$here/.." && pwd -P)), not from $(pwd -P)" 2

out= archive=
while [ $# -gt 0 ]; do
  case $1 in
    --out) [ $# -ge 2 ] || die "missing value for $1"; out=$2; shift 2;;
    --archive) [ $# -ge 2 ] || die "missing value for $1"; archive=$2; shift 2;;
    --) shift; break;;
    *) die "unknown argument: $1";;
  esac
done
[ -n "$out" ] && [ -d "$archive" ] || die "--out and --archive (a directory) are required"
for v_ in "$out" "$archive"; do [ "$(printf '%s' "$v_" | LC_ALL=C tr -d '\040-\176'; printf x)" = x ] || die "$v_ holds a control character or a byte outside printable ASCII; refusing, the path arguments are plain ASCII text" 2; done
a_=$archive; while [ "${a_%/}" != "$a_" ] && [ "$a_" != / ]; do a_=${a_%/}; done
o_=$out; while [ "${o_%/}" != "$o_" ] && [ "$o_" != / ]; do o_=${o_%/}; done
for x_ in "$a_" "$o_"; do q_=$x_; while [[ $q_ == ./* ]]; do q_=${q_#./}; done; while [[ $q_ == ../* ]]; do q_=${q_#../}; done; case "/$q_/" in */./*|*/../*) die "$x_ has a . or .. component after another component (it could hide a symlinked root); give the real path" 2;; esac; done
[ ! -L "$o_" ] || die "--out $out is a symlink; refusing (the results would be written through it)" 2
[ ! -L "$a_" ] || die "--archive $archive is a symlink; refusing (the copies of the proof would be made through it)"
[ -x "$here/assemble-image.sh" ] || die "assembly script not executable: $here/assemble-image.sh"
# the assembler runs from a copy of the repository root: every directory the caller gave is resolved to its physical absolute path first (the caller's
# spelling was already checked above), so ./x and ../x mean here what they mean to the assembler
absdir() { (cd -P -- "$1" 2>/dev/null && pwd -P) || printf '%s' "$1"; }
archive=$(absdir "$archive")
case $out in */*) out=$(absdir "${out%/*}")/${out##*/};; *) out=$(absdir .)/$out;; esac
pass=("$@")
for ((i = 0; i + 1 < ${#pass[@]}; i++)); do   # the directories the assembler is given: absolute, as the working directory changes
  case ${pass[$i]} in --melange-repo|--keyring-dir) pass[$((i + 1))]=$(absdir "${pass[$((i + 1))]}");; esac
done
for a in "${pass[@]}"; do case $a in --archive|--out|--render-dir|--apko-config|--base-lock|--index-record|--key-record) die "$a after --: this option is supplied by the proof; a forwarded value could be printed back by the assembler and mistaken for a reason" 2;; esac; done
variant= version= melrepo= keydir=
for ((i = 0; i < ${#pass[@]}; i += 2)); do   # the assembler's four options, each with its value; the assembler takes them in a fixed order
  case ${pass[$i]} in
    --variant) variant=${pass[$((i + 1))]:-};;
    --version) version=${pass[$((i + 1))]:-};;
    --melange-repo) melrepo=${pass[$((i + 1))]:-};;
    --keyring-dir) keydir=${pass[$((i + 1))]:-};;
    *) die "unknown argument after --: ${pass[$i]}" 2;;
  esac
done
root=$(cd "$here/.." && pwd)
case $variant in
  production) dcfg=$root/build/apko.yaml; dlock=$root/build/locks/apko.base.lock.json;;
  fips) dcfg=$root/build/apko-fips.yaml; dlock=$root/build/locks/apko-fips.base.lock.json;;
  *) die "the arguments after -- must include --variant production|fips";;
esac
baselock=$dlock
idxrec=$root/build/locks/archive-index.sha256
keyrec=$root/build/locks/archive-keys.sha256
srccfg=$dcfg
[ -f "$baselock" ] || die "the base lock $baselock is not a file (the victim is a package of the base lock)"
[ -f "$srccfg" ] || die "the config $srccfg is not a file"

tmp=$(mktemp -d)
cleanup() { local rc=$?; set +e; rm -rf "$tmp" 2>/dev/null || "$SUDO" rm -rf "$tmp" >/dev/null 2>&1; exit $rc; }
trap cleanup EXIT
[ ! -e "$out/lock-proof.json" ] && [ ! -L "$out/lock-proof.json" ] || die "$out/lock-proof.json already exists (or is a link): refusing to write through or over it; give an empty --out" 2
mkdir -p "$out"
inside_tmp() { case "$(cd -P -- "$1" && pwd -P)" in "$(cd -P -- "$tmp" && pwd -P)"/*) ;; *) die "internal: $1 is not inside the proof's own temp directory; refusing to modify it" 2;; esac; }   # before any rm or write

# mkrepo <name> [config]: a throwaway repository root: bin/ linked to the real one, build/ copied (the live-packages case changes the config of ITS copy)
mkrepo() {
  local r=$tmp/repo-$1 f
  mkdir -p "$r/bin"; inside_tmp "$r"
  for f in "$root"/bin/*; do ln -s "$f" "$r/bin/$(basename "$f")"; done
  cp -R "$root/build" "$r/build"
  [ -z "${2:-}" ] || cp "$2" "$r/build/$(basename "$dcfg")"
}
run() { # <name> <archive> [temp config]: the assembler runs from its own repository root copy with the committed inputs
  mkrepo "$1" "${3:-}"
  ( cd "$tmp/repo-$1" && "$BASHBIN" bin/assemble-image.sh --variant "$variant" --version "$version" --archive "$2" \
    --melange-repo "$melrepo" --keyring-dir "$keydir" --out "$tmp/out-$1" ) >"$tmp/$1.log" 2>&1 && rc=0 || rc=$?
}

# the victim: the first package of the BASE LOCK by (name, architecture)
victim=$("$PY3" -I -B - "$baselock" "lock-proof.sh" <<'PY'
import json, re, sys
e = sorted(json.load(open(sys.argv[1]))["contents"]["packages"], key=lambda e: (e["name"], e["architecture"]))[0]
def bad(what, v): print("%s: the base lock's first package has an unacceptable %s %r (closed rule: architecture exactly x86_64 or aarch64; name and version only [A-Za-z0-9._+-], never . or .. and never starting with -); refusing before any copy" % (sys.argv[2], what, v), file=sys.stderr); sys.exit(2)
if e["architecture"] not in ("x86_64", "aarch64"): bad("architecture", e["architecture"])
for k in ("name", "version"):
    v = e[k]
    if not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9._+-]+", v) or v in (".", "..") or v.startswith("-") or ".." in v: bad(k, v)
print("%s/%s-%s.apk" % (e["architecture"], e["name"], e["version"]))
PY
) || die "cannot read the base lock $baselock"
# 0. the positive control
run control "$archive"
[ "$rc" = 0 ] || { tail -5 "$tmp/control.log" >&2; die "positive control failed: the untouched archive and config did not assemble (exit $rc); a proof that cannot succeed proves nothing" 1; }

[ ! -L "$archive/$victim" ] || die "the victim $victim in the archive is a symlink; refusing (the proof must never write through a link)"
[ -f "$archive/$victim" ] || die "the base lock's first package $victim is not in the archive (the positive control passed, so this is a bad lock-proof setup)"
vname=$(basename "$victim"); arch_dir=$(dirname "$victim")
vre=$(printf '%s' "$vname" | sed 's/[][\.*^$+?(){}|/]/\\&/g')   # the name as a literal inside a regular expression

cp -RP "$archive" "$tmp/a-missing-package"; inside_tmp "$tmp/a-missing-package"; inside_tmp "$(dirname "$tmp/a-missing-package/$victim")"; rm -f "$tmp/a-missing-package/$victim"

cp -RP "$archive" "$tmp/a-missing-index"; inside_tmp "$tmp/a-missing-index"; inside_tmp "$tmp/a-missing-index/$arch_dir"; [ ! -e "$tmp/a-missing-index/$arch_dir/index" ] || inside_tmp "$tmp/a-missing-index/$arch_dir/index"; rm -rf "$tmp/a-missing-index/$arch_dir/APKINDEX.tar.gz" "$tmp/a-missing-index/$arch_dir"/index/APKINDEX-*.tar.gz   # the pointer AND the named index

cp -RP "$archive" "$tmp/a-tampered"; inside_tmp "$tmp/a-tampered"; inside_tmp "$(dirname "$tmp/a-tampered/$victim")"
[ ! -L "$tmp/a-tampered/$victim" ] && [ -f "$tmp/a-tampered/$victim" ] || die "internal: the copied victim $tmp/a-tampered/$victim is not a regular file (a link was put in its place); refusing to write through it"
"$PY3" -I -B - "$tmp/a-tampered/$victim" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, "rb").read())
if not b:
    raise SystemExit("the victim apk is empty")
b[len(b) // 2] ^= 0xFF; open(p, "wb").write(bytes(b))
PY

results=()
expect() { # <name> <archive> <temp config or -> <reason regex>
  local name=$1
  run "$name" "$2" "$([ "$3" = - ] || echo "$3")"
  [ "$rc" != 0 ] || die "case $name did not fail: the assembly accepted a bad input" 1
  [ "$rc" = 2 ] || die "case $name failed with exit $rc, not the named refusal exit 2 (the exit code must say it was a refusal)" 1
  grep -E '^(assemble-image|apko-lock)\.sh: ' "$tmp/$name.log" | grep -Eqi -- "$4" || die "case $name was refused (exit 2) but not for its own reason: the message does not match /$4/ (reason must be the case's own); got: $(tail -1 "$tmp/$name.log")" 1
  results+=("$name|$(grep -E '^(assemble-image|apko-lock)\.sh: ' "$tmp/$name.log" | grep -Ei -m1 -- "$4" | cut -c1-400)")
}

expect missing-package "$tmp/a-missing-package" - "$vre.* is not in the archive"
tre=$(printf '%s' "$tmp" | sed 's/[][\.*^$+?(){}|/]/\\&/g')
expect missing-index "$tmp/a-missing-index" - "$tre/a-missing-index/.*APKINDEX"
expect tampered-package "$tmp/a-tampered" - "$vre: .*(does not match|differs)"

sed 's#/work/archive#https://packages.wolfi.dev/os#' "$srccfg" >"$tmp/live.yaml"
expect live-packages "$archive" "$tmp/live.yaml" "live repository"

"$PY3" -I -B - "$out/lock-proof.json" "$root/bin/assemble-image.sh" "$srccfg" "$baselock" "$idxrec" "$keyrec" "${results[@]}" <<'PY'
import hashlib, json, os, sys
out, script = sys.argv[1:3]
sha = lambda p: {"path": p, "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest() if os.path.isfile(p) else "absent"}
inputs = dict(zip(("config", "base_lock", "index_record", "key_record"), map(sha, sys.argv[3:7])))
cases = {}
for r in sys.argv[7:]:
    name, reason = r.split("|", 1); cases[name] = {"result": "failed-as-required", "exit": 2, "reason": reason}
json.dump({"positive_control": "ok", "assemble_script": script, "assemble_script_sha256": hashlib.sha256(open(script, "rb").read()).hexdigest(),
           "inputs": inputs, "override_cases": ["live-packages"], "cases": cases}, open(out, "w"), indent=1, sort_keys=True)
open(out, "a").write("\n")
PY
echo "lock proof: the control assembled, and all four bad inputs were refused with their own reason (exit 2)"
