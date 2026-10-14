#!/usr/bin/env bash
# proves: REQ-VEND-001-AC2, REQ-VEND-001-AC3, REQ-VEND-001-AC11
# The vendored tree's regenerate-and-compare check (REQ-VEND-001, owner "code it" Oct 14): bin/vendor-check.sh, the vendor job in
# ci.yml, and the listable shape of the script. Offline: the Go fixture module is served from a file:// proxy and no step reaches the
# network. Run it from the repository root, with stdin closed. (The provenance file, its check and the vendored tree ship in the
# later vendored-tree PR with the rest of REQ-VEND-001.)
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
work=$(mktemp -d); trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
pass=0 failn=0
ok()  { pass=$((pass+1)); }
bad() { failn=$((failn+1)); echo "FAIL [$1] $2"; }
t()  { local ac=$1 d=$2; shift 2; if "$@" >"$work/out" 2>&1; then ok; else bad "$ac" "$d"; fi; }
bin_vc="$root/bin/vendor-check.sh"
# rc: passes when the command exits with exactly the code (a missing tool is a failure, never a pass)
rc() { local ac=$1 d=$2 want=$3; shift 3; if [ ! -e "$bin_vc" ]; then bad "$ac" "$d (tool missing)"; return; fi
       "$@" >"$work/out" 2>&1 </dev/null; local got=$?; if [ "$got" = "$want" ]; then ok; else bad "$ac" "$d (exit $got, want $want)"; fi; }
# says: passes when the last output of rc/t holds the text
says() { local ac=$1 d=$2 text=$3; if grep -qF -- "$text" "$work/out"; then ok; else bad "$ac" "$d (output lacks: $text)"; fi; }
vc() { bash "$bin_vc" "$@"; }

# ===== AC2: the regenerate-and-compare (a fixture module through a file:// proxy; offline) =====
fx="$work/gofix"; proxy="$work/proxy"; mkdir -p "$proxy/example.test/dep/@v" "$fx"
python3 - "$proxy" <<'PY'
import sys, zipfile, json
p = sys.argv[1] + "/example.test/dep/@v"
open(p + "/list", "w").write("v1.0.0\n")
open(p + "/v1.0.0.info", "w").write(json.dumps({"Version": "v1.0.0", "Time": "2024-01-01T00:00:00Z"}))
open(p + "/v1.0.0.mod", "w").write("module example.test/dep\n\ngo 1.20\n")
with zipfile.ZipFile(p + "/v1.0.0.zip", "w") as z:
    z.writestr("example.test/dep@v1.0.0/go.mod", "module example.test/dep\n\ngo 1.20\n")
    z.writestr("example.test/dep@v1.0.0/dep.go", "package dep\n\nfunc Name() string { return \"dep\" }\n")
PY
printf 'module example.test/app\n\ngo 1.20\n\nrequire example.test/dep v1.0.0\n' >"$fx/go.mod"
printf 'package main\n\nimport "example.test/dep"\n\nfunc main() { println(dep.Name()) }\n' >"$fx/main.go"
export GOPROXY="file://$proxy" GOSUMDB=off GOFLAGS=-mod=mod GOMODCACHE="$work/modcache" GOCACHE="$work/gocache" GOTOOLCHAIN=local
( cd "$fx" && go mod tidy && go mod vendor ) >"$work/fixsetup.log" 2>&1 || echo "fixture setup failed: $(tail -3 "$work/fixsetup.log")"
H1=h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
cp -R "$fx" "$work/fx-clean"
rc AC2 "a clean fixture tree passes the regeneration check" 0 vc "$work/fx-clean"
mkcase() { rm -rf "$work/fx-$1"; cp -R "$fx" "$work/fx-$1"; }
dep() { find "$work/fx-$1/vendor/example.test" -name dep.go; }
mkcase byte;  printf 'X' | dd of="$(dep byte)" bs=1 seek=0 count=1 conv=notrunc 2>/dev/null
mkcase add;   echo "package dep" >"$work/fx-add/vendor/example.test/dep/extra.go"
mkcase del;   rm "$(dep del)"
mkcase mtxt;  echo "# stray" >>"$work/fx-mtxt/vendor/modules.txt"
mkcase gosum; echo "example.test/dep v1.0.0 $H1" >"$work/fx-gosum/go.sum"
mkcase dot;   echo "x" >"$work/fx-dot/vendor/.hidden"
mkcase dotdir; mkdir -p "$work/fx-dotdir/vendor/.github" && echo "x" >"$work/fx-dotdir/vendor/.github/w.yml"
mkcase emptydir; mkdir -p "$work/fx-emptydir/vendor/example.test/dep/sub"   # what a checked-out gitlink looks like
mkcase symfile; ln -s dep.go "$work/fx-symfile/vendor/example.test/dep/link.go"
mkcase symrepl; f=$(dep symrepl); rm "$f"; ln -s "$work/fx-clean/vendor/example.test/dep/dep.go" "$f"   # same bytes through a link
mkcase symdir;  ln -s dep "$work/fx-symdir/vendor/example.test/depl"
mkcase fifo;    mkfifo "$work/fx-fifo/vendor/example.test/dep/pipe"
mkcase exec;    chmod 755 "$(dep exec)"
for c in byte add del mtxt gosum dot dotdir emptydir symfile symrepl symdir fifo exec; do
  rc AC2 "the regeneration check refuses: $c" 1 vc "$work/fx-$c"
done
rc AC2 "(byte case) the failure names the changed path" 1 vc "$work/fx-byte"
says AC2 "(byte case) the failure names dep.go" "dep.go"
rc AC2 "(exec case) the failure names the mode" 1 vc "$work/fx-exec"
says AC2 "(exec case) the failure says mode" "mode"
rc AC2 "an unknown argument exits 2" 2 vc --frobnicate
rc AC2 "two arguments exit 2" 2 vc "$work/fx-clean" extra
rc AC2 "an unreadable tree exits 2" 2 vc "$work/does-not-exist"
mkdir -p "$work/nogo"; cp -R "$fx/vendor" "$work/nogo/vendor"
rc AC2 "a tree with vendor/ but no go.mod or go.sum exits 2" 2 vc "$work/nogo"
# fail closed: a proxy that cannot serve the module, and a toolchain that is not there, are failures, never a pass
mkdir -p "$work/emptybin"
rc AC2 "an unreachable proxy fails (1)" 1 env GOPROXY="file://$work/no-such-proxy" GOMODCACHE="$work/modcache-empty" bash "$bin_vc" "$work/fx-clean"
rc AC2 "a missing go toolchain fails (1)" 1 env PATH="$work/emptybin" /bin/bash "$bin_vc" "$work/fx-clean"
says AC2 "(missing toolchain) the failure names the toolchain" "go toolchain not found"

# the narrow no-vendor branch (advisor ruling Oct 14): passes, with the printed line, only when vendor/ is absent from BOTH origin/main
# and the tree under test; any vendor path anywhere in the tree runs the full check; every other oddity fails
mkgit() { # NAME: a git work tree with go.mod/go.sum, a commit, and refs/remotes/origin/main at that commit
  local d="$work/g-$1"; rm -rf "$d"; mkdir -p "$d"
  cp "$fx/go.mod" "$fx/go.sum" "$fx/main.go" "$d/"
  ( cd "$d" && git init -q && git add -A && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm base \
      && git update-ref refs/remotes/origin/main HEAD ) >/dev/null 2>&1
}
mkgit absent
rc AC2 "no vendor/ here and none on origin/main: passes" 0 vc "$work/g-absent"
says AC2 "(absent case) the pass line is printed" "no vendor/ in this tree and none on origin/main"
mkgit basehas
( cd "$work/g-basehas" && cp -R "$fx/vendor" vendor && git add -A && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm v \
    && git update-ref refs/remotes/origin/main HEAD && git rm -rq --cached vendor && rm -rf vendor && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm rmv ) >/dev/null 2>&1
rc AC2 "vendor/ deleted in the tree but present on origin/main: fails (1)" 1 vc "$work/g-basehas"
mkgit nobase
( cd "$work/g-nobase" && git update-ref -d refs/remotes/origin/main ) >/dev/null 2>&1
rc AC2 "origin/main cannot be read: fails (1)" 1 vc "$work/g-nobase"
mkdir -p "$work/g-nogit"; cp "$fx/go.mod" "$fx/go.sum" "$work/g-nogit/"
rc AC2 "no git tree to read origin/main from: fails (1)" 1 vc "$work/g-nogit"
mkgit nested;   mkdir -p "$work/g-nested/pkg/vendor" && echo x >"$work/g-nested/pkg/vendor/x.go"
rc AC2 "a vendor path below the top, none at the top: full check, refused (2)" 2 vc "$work/g-nested"
mkgit vfile;    echo x >"$work/g-vfile/vendor"
rc AC2 "a regular file named vendor: refused (2)" 2 vc "$work/g-vfile"
mkgit vlink;    ln -s /tmp "$work/g-vlink/vendor"
rc AC2 "a symlink named vendor: refused (2)" 2 vc "$work/g-vlink"
mkgit full;     cp -R "$fx/vendor" "$work/g-full/vendor"
rc AC2 "vendor/ present and equal to the regenerated tree: full check passes" 0 vc "$work/g-full"
mkgit fullbad;  cp -R "$fx/vendor" "$work/g-fullbad/vendor"; echo "package dep" >"$work/g-fullbad/vendor/example.test/dep/extra.go"
rc AC2 "vendor/ present with an extra file: full check refuses (1)" 1 vc "$work/g-fullbad"
unset GOPROXY GOSUMDB GOFLAGS GOMODCACHE GOCACHE GOTOOLCHAIN

# ===== AC3: the vendor job ====================================================================
J="$work/vendorjob.py"
cat >"$J" <<'PY'
import re, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
job = d.get("jobs", {}).get("vendor")
assert job, "ci.yml has no job named vendor"
assert "pull_request" in (d.get("on") or {}), "ci.yml does not run on pull_request"
ro = str(job.get("runs-on", "")); assert ro.startswith("ubuntu-") and "self-hosted" not in ro, "runs-on " + ro
steps = "\n".join((s.get("run") or "") for s in job.get("steps", []))
assert "go mod verify" in steps, "no go mod verify"
assert "bin/vendor-check.sh" in steps, "no bin/vendor-check.sh"
blob = open(sys.argv[1]).read()
assert not re.search(r"GOSUMDB\s*[:=]\s*[\"']?off|GONOSUMDB|GONOSUMCHECK|GOPRIVATE|-insecure|GOFLAGS[^\n]*-mod=mod", blob), "sumdb opt-out or -mod=mod"
for x in [job] + list(job.get("steps", [])):
    v = str(x.get("if", ""))
    assert "dependabot" not in v.lower() and "actor" not in v and "head_ref" not in v and "ref_name" not in v, "the job or a step skips by actor or branch: " + v
    assert str(x.get("continue-on-error", "false")).lower() != "true", "continue-on-error"
uses = [s.get("uses", "") for s in job.get("steps", []) if s.get("uses")]
assert uses and all(re.search(r"@[0-9a-f]{40}$", u.split(" ")[0]) for u in uses), "an action is not a commit digest: " + str(uses)
co = [s for s in job.get("steps", []) if str(s.get("uses", "")).startswith("actions/checkout@")]
assert co and str((co[0].get("with") or {}).get("fetch-depth", "")) == "0", "checkout must fetch history so origin/main is readable (fetch-depth: 0)"
PY
t AC3 "ci.yml vendor job: PR trigger, hosted runner, go mod verify + vendor-check, no opt-out, no skip, digest pins, history fetched" python3 "$J" "$root/.github/workflows/ci.yml"

# ===== AC11: listable shape =======================================================================
f=bin/vendor-check.sh
t AC11 "$f has a shebang and mode 100755 in git" bash -c "[ -e '$f' ] && head -1 '$f' | grep -q '^#!' && git ls-files -s '$f' | grep -q '^100755'"
t AC11 "$f assigns none of PATH IFS BASH_ENV ENV LD_* PYTHON*" bash -c "[ -e '$f' ] && ! grep -Eq '(^|[^A-Za-z0-9_])(PATH|IFS|BASH_ENV|ENV|LD_[A-Z_]+|PYTHON[A-Z_]*)[+]?=' '$f'"
t AC11 "$f runs no python3 -c and no here-document interpreter" bash -c "[ -e '$f' ] && ! grep -Eq 'python3? +-c|python3? +-( |$)|<<' '$f'"
t AC11 "$f builds no command word by substitution" bash -c "[ -e '$f' ] && ! grep -Eq '^[[:space:]]*(\\\$\\(|\\\`)' '$f'"
rc AC11 "vendor-check.sh exits 2 outside the repository root" 2 bash -c "cd '$work' && bash '$bin_vc'"

echo "vendoring-test: $pass passed, $failn failed"
[ "$failn" = 0 ]
