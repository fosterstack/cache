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
# a module whose package embeds a dot file: go mod vendor copies it, so regeneration alone would accept it
python3 - "$proxy" <<'PY'
import sys, zipfile, json, os
p = sys.argv[1] + "/example.test/emb/@v"
os.makedirs(p, exist_ok=True)
open(p + "/list", "w").write("v1.0.0\n")
open(p + "/v1.0.0.info", "w").write(json.dumps({"Version": "v1.0.0", "Time": "2024-01-01T00:00:00Z"}))
open(p + "/v1.0.0.mod", "w").write("module example.test/emb\n\ngo 1.20\n")
with zipfile.ZipFile(p + "/v1.0.0.zip", "w") as z:
    z.writestr("example.test/emb@v1.0.0/go.mod", "module example.test/emb\n\ngo 1.20\n")
    z.writestr("example.test/emb@v1.0.0/.hidden", "secret\n")
    z.writestr("example.test/emb@v1.0.0/emb.go", "package emb\n\nimport _ \"embed\"\n\n//go:embed .hidden\nvar hidden string\n\nfunc Name() string { return hidden }\n")
PY
fxe="$work/gofix-emb"; mkdir -p "$fxe"
printf 'module example.test/app2\n\ngo 1.20\n\nrequire example.test/emb v1.0.0\n' >"$fxe/go.mod"
printf 'package main\n\nimport "example.test/emb"\n\nfunc main() { println(emb.Name()) }\n' >"$fxe/main.go"
( cd "$fxe" && go mod tidy && go mod vendor ) >"$work/fixsetup2.log" 2>&1 || echo "embed fixture setup failed: $(tail -3 "$work/fixsetup2.log")"
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
mkcase m600;    chmod 600 "$(dep m600)"
mkcase m666;    chmod 666 "$(dep m666)"
mkcase m444;    chmod 444 "$(dep m444)"
for c in byte add del mtxt gosum dot dotdir emptydir symfile symrepl symdir fifo exec m600 m666 m444; do
  rc AC2 "the regeneration check refuses: $c" 1 vc "$work/fx-$c"
done
rc AC2 "(byte case) the failure names the changed path" 1 vc "$work/fx-byte"
says AC2 "(byte case) the failure names dep.go" "dep.go"
rc AC2 "(exec case) the failure names the mode" 1 vc "$work/fx-exec"
says AC2 "(exec case) the failure says mode" "mode"
mkcase lnksum;  cp "$work/fx-lnksum/go.sum" "$work/lnksum-target" && rm "$work/fx-lnksum/go.sum" && ln -s "$work/lnksum-target" "$work/fx-lnksum/go.sum"
rc AC2 "a go.sum that is a link is refused (2): a repair would land in the link's target and hide from the comparison" 2 vc "$work/fx-lnksum"
mkcase lnkmod;  cp "$work/fx-lnkmod/go.mod" "$work/lnkmod-target" && rm "$work/fx-lnkmod/go.mod" && ln -s "$work/lnkmod-target" "$work/fx-lnkmod/go.mod"
rc AC2 "a go.mod that is a link is refused (2)" 2 vc "$work/fx-lnkmod"
# a toolchain whose regenerated files are not mode 644 (whatever the umask): the regenerated tree is judged for mode too
realgo=$(command -v go); mkdir -p "$work/modego"
printf '#!/bin/sh\n"%s" "$@"; rc=$?; if [ "$1 $2" = "mod vendor" ]; then find vendor -name dep.go -exec chmod 600 {} +; fi; exit $rc\n' "$realgo" >"$work/modego/go"; chmod 755 "$work/modego/go"
rc AC2 "regenerated files that are not mode 644 are refused (1)" 1 env PATH="$work/modego:$PATH" bash "$bin_vc" "$work/fx-clean"
rc AC2 "a caller's umask 077 does not change the verdict on a clean tree (0)" 0 bash -c "umask 077; bash '$bin_vc' '$work/fx-clean'"
# go mod verify itself must be what refuses a module cache that was altered; vendoring never runs after it
cp -R "$work/modcache" "$work/modcache-bad"; chmod -R u+w "$work/modcache-bad"
find "$work/modcache-bad" -name dep.go -exec sh -c 'echo "// altered" >>"$1"' _ {} \;
rc AC2 "a module cache that go mod verify refuses is a failure (1)" 1 env GOMODCACHE="$work/modcache-bad" bash "$bin_vc" "$work/fx-clean"
says AC2 "(verify failure) the failure names go mod verify" "go mod verify failed"
cp "$fx/go.mod" "$work/fx-clean/alternate.mod"; cp "$fx/go.sum" "$work/fx-clean/alternate.sum"
rc AC2 "GOFLAGS that redirects the module file (-modfile) is refused (2): the committed go.sum is what is judged" 2 env GOFLAGS='-mod=mod -modfile=alternate.mod' bash "$bin_vc" "$work/fx-clean"
rc AC2 "GOFLAGS with -overlay is refused (2)" 2 env GOFLAGS='-mod=mod -overlay=x.json' bash "$bin_vc" "$work/fx-clean"
rc AC2 "GOFLAGS with -o is refused (2)" 2 env GOFLAGS='-o=/tmp/x' bash "$bin_vc" "$work/fx-clean"
rc AC2 "an empty GOFLAGS is accepted (0)" 0 env GOFLAGS= bash "$bin_vc" "$work/fx-clean"
# an empty directory that regeneration itself reproduces (a package directory whose only sources were links): refused, by name
mkdir -p "$work/emptygo"; printf '#!/bin/sh\n"%s" "$@"; rc=$?; if [ "$1 $2" = "mod vendor" ]; then mkdir -p vendor/example.test/dep/emptied; fi; exit $rc\n' "$realgo" >"$work/emptygo/go"; chmod 755 "$work/emptygo/go"
mkcase emptyboth; mkdir -p "$work/fx-emptyboth/vendor/example.test/dep/emptied"
rc AC2 "an empty directory that regeneration also produces is refused (1)" 1 env PATH="$work/emptygo:$PATH" bash "$bin_vc" "$work/fx-emptyboth"
says AC2 "(empty directory) the failure names the empty directory and its name" "emptied"
# GOFLAGS from the Go tool's own configuration file is the effective value: judged like the environment's
printf 'GOFLAGS=-mod=mod -modfile=alternate.mod\n' >"$work/go.env"
rc AC2 "a -modfile set through GOENV's file is refused (2)" 2 env -u GOFLAGS GOENV="$work/go.env" bash "$bin_vc" "$work/fx-clean"
printf 'GOFLAGS=-o=/tmp/x\n' >"$work/go-o.env"
rc AC2 "an -o set through GOENV's file is refused (2)" 2 env -u GOFLAGS GOENV="$work/go-o.env" bash "$bin_vc" "$work/fx-clean"
# every Go invocation (go env GOFLAGS, go mod verify, go mod vendor) runs with GOAUTH=off, and verification comes before vendoring and stops it
mkdir -p "$work/reccgo"; printf '#!/bin/sh\necho "$* GOAUTH=${GOAUTH-unset}" >>"$RECORD"\nexec "%s" "$@"\n' "$realgo" >"$work/reccgo/go"; chmod 755 "$work/reccgo/go"
rm -f "$work/rec.txt"; rc AC2 "a clean tree with a recording go: passes (0)" 0 env RECORD="$work/rec.txt" GOAUTH=audit-sentinel PATH="$work/reccgo:$PATH" bash "$bin_vc" "$work/fx-clean"
t AC2 "every go invocation ran with GOAUTH=off (env, verify, vendor)" bash -c "[ \$(wc -l <'$work/rec.txt') -ge 3 ] && ! grep -v 'GOAUTH=off\$' '$work/rec.txt'"
t AC2 "go env GOFLAGS comes first, then mod verify, then mod vendor" bash -c "[ \"\$(sed -n 1p '$work/rec.txt' | cut -d' ' -f1-2)\" = 'env GOFLAGS' ] && grep -n 'mod verify' '$work/rec.txt' | head -1 | grep -q '^2:' && grep -n 'mod vendor' '$work/rec.txt' | head -1 | grep -q '^3:'"
rm -f "$work/rec.txt"; rc AC2 "verify failure with a recording go (1)" 1 env RECORD="$work/rec.txt" GOMODCACHE="$work/modcache-bad" PATH="$work/reccgo:$PATH" bash "$bin_vc" "$work/fx-clean"
t AC2 "after a failed go mod verify, go mod vendor never ran" bash -c "grep -q 'mod verify' '$work/rec.txt' && ! grep -q 'mod vendor' '$work/rec.txt'"
rc AC2 "an unknown argument exits 2" 2 vc --frobnicate
rc AC2 "two arguments exit 2" 2 vc "$work/fx-clean" extra
rc AC2 "an unreadable tree exits 2" 2 vc "$work/does-not-exist"
mkcase noperm; chmod 000 "$work/fx-noperm/vendor"
rc AC2 "a tree whose vendor/ cannot be read is a failure, never a pass (1)" 1 vc "$work/fx-noperm"
chmod 755 "$work/fx-noperm/vendor"
for pair in "symfile:link.go" "symdir:depl" "fifo:pipe" "emptydir:sub" "add:extra.go" "dot:.hidden" "dotdir:.github"; do
  c=${pair%%:*}; nm=${pair#*:}
  rc AC2 "($c case) refused (1)" 1 vc "$work/fx-$c"
  says AC2 "($c case) the failure names the offending path $nm" "$nm"
done
mkdir -p "$work/nogo"; cp -R "$fx/vendor" "$work/nogo/vendor"
rc AC2 "a tree with vendor/ but no go.mod or go.sum exits 2" 2 vc "$work/nogo"
# fail closed: a proxy that cannot serve the module, and a toolchain that is not there, are failures, never a pass
# ruling D (advisor, Oct 14): a dot-named FILE is allowed exactly when it is what go mod vendor regenerates, byte for byte and mode 100644
rc AC2 "an embedded dot file that go mod vendor regenerates passes (0)" 0 vc "$fxe"
t AC2 "(embedded dot file) the vendored tree builds" bash -c "cd '$fxe' && GOFLAGS=-mod=vendor GOPROXY=off go build ./..."
rm -rf "$work/fx-dotbyte" "$work/fx-dotmode" "$work/fx-dotextra"; cp -R "$fxe" "$work/fx-dotbyte"; cp -R "$fxe" "$work/fx-dotmode"; cp -R "$fxe" "$work/fx-dotextra"
echo "changed" >"$work/fx-dotbyte/vendor/example.test/emb/.hidden"
chmod 600 "$work/fx-dotmode/vendor/example.test/emb/.hidden"
echo x >"$work/fx-dotextra/vendor/example.test/emb/.extra"
rc AC2 "a regenerated dot file with a changed byte is refused (1)" 1 vc "$work/fx-dotbyte"
rc AC2 "a regenerated dot file that is not mode 644 is refused (1)" 1 vc "$work/fx-dotmode"
rc AC2 "a dot file that regeneration does not produce is refused (1)" 1 vc "$work/fx-dotextra"
rc AC2 "a dot DIRECTORY is refused (1), by name" 1 vc "$work/fx-dotdir"
says AC2 "(dot directory) the failure names the dot directory" "dot directory"
mkcase gosumempty; : >"$work/fx-gosumempty/go.sum"
rc AC2 "a go.sum that go mod vendor would have to repair is refused (1), with GOFLAGS=-mod=mod in the caller's environment" 1 vc "$work/fx-gosumempty"
mkcase gomodedit; printf 'module example.test/app\n\ngo 1.20\n' >"$work/fx-gomodedit/go.mod"   # the require line is missing: go mod vendor (GOFLAGS=-mod=mod) would add it
rc AC2 "a go.mod that go mod vendor has to rewrite is refused (1)" 1 vc "$work/fx-gomodedit"
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
mkdir -p "$work/findfail"; printf '#!/bin/sh\nexit 1\n' >"$work/findfail/find"; chmod 755 "$work/findfail/find"
rc AC2 "a listing of the tree that fails is no proof of absence: fails (1)" 1 env PATH="$work/findfail:$PATH" bash "$bin_vc" "$work/g-absent"
for nm in "vendor/a	b.go" "vendor/caf$(printf '\303\251').go" 'vendor/a"b.go'; do
  mkgit quoted
  ( cd "$work/g-quoted" && mkdir -p vendor && : >"$nm" && git add -A && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm q \
      && git update-ref refs/remotes/origin/main HEAD && git rm -rq --cached vendor && rm -rf vendor && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm rmq ) >/dev/null 2>&1
  rc AC2 "a vendor path with an unusual name on origin/main is found (1): $(printf '%s' "$nm" | tr '\t' '~')" 1 vc "$work/g-quoted"
done
mkgit alias;    mkdir -p "$work/g-alias/pkg/vendor" && echo x >"$work/g-alias/pkg/vendor/x.go"; ln -sfn "$work/g-alias" "$work/alias"
rc AC2 "a ROOT that is a link to a tree with a nested vendor path is judged through the link: refused (2)" 2 vc "$work/alias"
mkgit subroot
( cd "$work/g-subroot" && mkdir -p vendor sub && echo x >vendor/x && echo x >sub/x && git add -A && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm v \
    && git update-ref refs/remotes/origin/main HEAD ) >/dev/null 2>&1
rc AC2 "a ROOT that is a subdirectory of its git tree is refused (2), never judged as the whole tree" 2 vc "$work/g-subroot/sub"
mkgit shadow
( cd "$work/g-shadow" && mkdir vendor && echo x >vendor/x && git add -A && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm v \
    && git update-ref refs/remotes/origin/main HEAD && git rm -rq --cached vendor && rm -rf vendor && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm r \
    && git update-ref refs/tags/origin/main HEAD ) >/dev/null 2>&1
rc AC2 "a tag named origin/main does not stand in for the remote-tracking branch: vendor/ on the real origin/main fails (1)" 1 vc "$work/g-shadow"
mkgit emptyv
( cd "$work/g-emptyv" && e=$(git mktree </dev/null) && t=$(printf '040000 tree %s\tvendor\n' "$e" | git mktree) \
    && c=$(git -c user.name=t -c user.email=t@t commit-tree "$t" -m ev) && git update-ref refs/remotes/origin/main "$c" ) >/dev/null 2>&1
rc AC2 "an empty vendor directory on origin/main is a vendor component: fails (1)" 1 vc "$work/g-emptyv"
mkgit nested;   mkdir -p "$work/g-nested/pkg/vendor" && echo x >"$work/g-nested/pkg/vendor/x.go"
rc AC2 "a vendor path below the top, none at the top: full check, refused (2)" 2 vc "$work/g-nested"
mkgit vfile;    echo x >"$work/g-vfile/vendor"
rc AC2 "a regular file named vendor: refused (2)" 2 vc "$work/g-vfile"
mkgit vlink;    ln -s /tmp "$work/g-vlink/vendor"
rc AC2 "a symlink named vendor: refused (2)" 2 vc "$work/g-vlink"
mkgit full;     cp -R "$fx/vendor" "$work/g-full/vendor"
git -C "$work/g-full" add -A vendor >/dev/null 2>&1
rc AC2 "vendor/ present and equal to the regenerated tree: full check passes" 0 vc "$work/g-full"
mkgit fullbad;  cp -R "$fx/vendor" "$work/g-fullbad/vendor"; echo "package dep" >"$work/g-fullbad/vendor/example.test/dep/extra.go"
rc AC2 "vendor/ present with an extra file: full check refuses (1)" 1 vc "$work/g-fullbad"
# ruling D: the git-acting files. A vendored .gitattributes is read (committed content): `text` set and `eol=lf` are the only text/eol
# forms that pass; every other form of text, eol, crlf, binary, diff, merge, filter, ident, export-ignore, export-subst,
# working-tree-encoding and every [attr] macro fails, and so does a line the parser cannot read.
mkattr() { # NAME CONTENT [ignore]: a one-module app whose vendored module carries a .gitattributes (and a .gitignore hiding extra.txt)
  local n=$1 d="$work/fa-$1"; rm -rf "$d"; mkdir -p "$d"
  python3 - "$proxy" "$n" "$2" "${3:-}" <<'PY'
import sys, zipfile, json, os
proxy, n, attrs, ign = sys.argv[1:5]
mod = "example.test/ga-" + n
if attrs == "@BIG":
    attrs = "#" + "a" * 1100000 + "\n*.go text\n"
p = proxy + "/" + mod + "/@v"; os.makedirs(p, exist_ok=True)
open(p + "/list", "w").write("v1.0.0\n")
open(p + "/v1.0.0.info", "w").write(json.dumps({"Version": "v1.0.0", "Time": "2024-01-01T00:00:00Z"}))
open(p + "/v1.0.0.mod", "w").write("module %s\n\ngo 1.20\n" % mod)
with zipfile.ZipFile(p + "/v1.0.0.zip", "w") as z:
    z.writestr("%s@v1.0.0/go.mod" % mod, "module %s\n\ngo 1.20\n" % mod)
    z.writestr("%s@v1.0.0/ga.go" % mod, "package ga\n\nfunc N() int { return 1 }\n")
    z.writestr("%s@v1.0.0/.gitattributes" % mod, attrs.encode("utf-8", "surrogateescape"))
    z.writestr("%s@v1.0.0/extra.txt" % mod, "x\n")
    if ign:
        z.writestr("%s@v1.0.0/.gitignore" % mod, "extra.txt\n")
PY
  printf 'module example.test/appga\n\ngo 1.20\n\nrequire example.test/ga-%s v1.0.0\n' "$n" >"$d/go.mod"
  printf 'package main\n\nimport "example.test/ga-%s"\n\nfunc main() { println(ga.N()) }\n' "$n" >"$d/main.go"
  ( cd "$d" && go mod tidy && go mod vendor ) >"$work/fixattr.log" 2>&1 || echo "attr fixture $n setup failed: $(tail -3 "$work/fixattr.log")"
}
mkattr ok "$(printf '# comment\n\n*.go text eol=lf\n*.md linguist-vendored\n*.txt linguist-generated=true\n')"
rc AC2 "a vendored .gitattributes with text eol=lf and linguist attributes passes (0)" 0 vc "$work/fa-ok"
mkattr realbbolt "$(printf '# ensure that line endings for Windows builds are properly formatted\n# see https://github.com/golangci/golangci-lint-action?tab=readme-ov-file#how-to-use\n# at "Multiple OS Example" section\n*.go text eol=lf\n')"
rc AC2 "the real go.etcd.io/bbolt .gitattributes passes (0)" 0 vc "$work/fa-realbbolt"
i=0
while IFS= read -r attr; do
  i=$((i+1)); mkattr "bad$i" "$(printf '# c\n%s\n' "$attr")"
  rc AC2 "a vendored .gitattributes line is refused (1): $attr" 1 vc "$work/fa-bad$i"
done <<'EOF'
*.go -text
*.go !text
*.go text=auto
*.go text=lf
*.go eol=crlf
*.go eol=native
*.go text eol=lf whitespace=-blank-at-eol
*.go text eol=lf conflict-marker-size=32
*.go text eol=lf unknownattr
*.go text eol=lf unknownattr=1
*.go whitespace
*.go eol=LF
*.go -eol
*.go !eol
*.go crlf
*.go -crlf
*.go binary
*.go -binary
*.go working-tree-encoding=UTF-16
*.go export-ignore
*.go -export-ignore
*.go export-subst
*.go filter=lfs
*.go -filter
*.go diff=word
*.go -diff
*.go !diff
*.go merge=union
*.go -merge
*.go ident
*.go linguist-vendored text=auto
[attr]mymacro -diff
[attr]vendored linguist-vendored
"*.go text
*.go text eol=lf=x
*.go =text
*.go --text
EOF
mkattr cr "$(printf '*.go text eol=lf\r')"
rc AC2 "a .gitattributes line the parser cannot read (CR) is refused (1)" 1 vc "$work/fa-cr"
mkattr nonascii "$(printf '# caf\303\251\n*.go text\n')"
rc AC2 "a .gitattributes that is not plain text the parser reads (non-ASCII) is refused (1)" 1 vc "$work/fa-nonascii"
mkattr big "@BIG"
rc AC2 "a .gitattributes over 1 MB is refused (1)" 1 vc "$work/fa-big"
mkattr named "$(printf '# c\n*.go text\n*.go export-ignore\n')"
rc AC2 "(forbidden attribute) the failure names the file and the line" 1 vc "$work/fa-named"
says AC2 "(forbidden attribute) .gitattributes:3" ".gitattributes:3"

# ruling D: in a git work tree the index is judged too: the tracked paths are the regenerated paths, each blob the regenerated bytes, mode 100644
gv() { mkgit "$1"; cp -R "$fx/vendor" "$work/g-$1/vendor"; }
gadd() { git -C "$work/g-$1" add -A vendor >/dev/null 2>&1; }
gv gitnone
rc AC2 "vendor/ equal to the regenerated tree but not tracked in the index: refused (1)" 1 vc "$work/g-gitnone"
gv gitexec; gadd gitexec; git -C "$work/g-gitexec" update-index --chmod=+x vendor/example.test/dep/dep.go >/dev/null 2>&1
rc AC2 "a tracked vendored file with index mode 100755: refused (1)" 1 vc "$work/g-gitexec"
gv gitblob; gadd gitblob
hb=$(printf 'other\n' | git -C "$work/g-gitblob" hash-object -w --stdin)
git -C "$work/g-gitblob" update-index --cacheinfo "100644,$hb,vendor/example.test/dep/dep.go" >/dev/null 2>&1
rc AC2 "a tracked blob that is not the regenerated bytes (a checkout conversion): refused (1)" 1 vc "$work/g-gitblob"
gv gitmissing; gadd gitmissing; git -C "$work/g-gitmissing" rm --cached -q vendor/example.test/dep/dep.go >/dev/null 2>&1
rc AC2 "a regenerated path that is not tracked: refused (1)" 1 vc "$work/g-gitmissing"
gv gitok; gadd gitok
rc AC2 "every regenerated path tracked, blobs equal, mode 100644: passes (0)" 0 vc "$work/g-gitok"
mkattr ign "$(printf '*.go text eol=lf\n')" ignore
rm -rf "$work/g-ign"; cp -R "$work/fa-ign" "$work/g-ign"
( cd "$work/g-ign" && git init -q && git add -A && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -qm base ) >/dev/null 2>&1
rc AC2 "a vendored .gitignore that leaves a regenerated file untracked: refused (1)" 1 vc "$work/g-ign"
( cd "$work/g-ign" && git add -f vendor ) >/dev/null 2>&1
rc AC2 "the same tree with the ignored file force-added: passes (0)" 0 vc "$work/g-ign"
unset GOPROXY GOSUMDB GOFLAGS GOMODCACHE GOCACHE GOTOOLCHAIN

# ===== AC3: the vendor job ====================================================================
J="$work/vendorjob.py"
cat >"$J" <<'PY'
import re, sys, yaml
d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
fail = lambda m: sys.exit("vendor job: " + m)
on = d.get("on")
pr = on.get("pull_request") if isinstance(on, dict) else (True if isinstance(on, list) and "pull_request" in on else None)
if pr is None and not (isinstance(on, list) and "pull_request" in on):
    fail("ci.yml does not run on pull_request")
if pr not in ("", None, True) and pr != {}:
    fail("pull_request carries a filter: " + str(pr))
job = d.get("jobs", {}).get("vendor")
if not job: fail("ci.yml has no job named vendor")
if job.get("name") != "vendor": fail("the job's check name is " + str(job.get("name")) + ", not vendor")
if d.get("defaults"): fail("a workflow-level defaults block (a shell default can skip every step)")
if d.get("env"): fail("a workflow-level env block (SHELLOPTS, BASH_ENV and the like change what a step runs)")
ro = str(job.get("runs-on", ""))
if ro not in ("ubuntu-latest", "ubuntu-24.04", "ubuntu-22.04"): fail("runs-on " + ro + " is not a GitHub-hosted ubuntu label")
if set(job) - {"name", "runs-on", "permissions", "steps"}: fail("job keys beyond name, runs-on, permissions, steps: " + str(sorted(job)))
if job.get("permissions") != {"contents": "read"}: fail("permissions " + str(job.get("permissions")))
steps = job.get("steps", [])
runs = [s for s in steps if "run" in s]
want = ["go mod verify", "bash bin/vendor-check.sh", "python3 bin/vendor-provenance.py check --vendor-dir vendor --go-sum go.sum --provenance dependency-provenance.json"]
if [s["run"].strip() for s in runs] != want: fail("run steps are not exactly go mod verify, bash bin/vendor-check.sh, then the provenance check: " + str([s["run"] for s in runs]))
allowed = {"name", "uses", "with", "run"}
for s in steps:
    if set(s) - allowed: fail("a step key beyond name, uses, with, run: " + str(sorted(set(s) - allowed)))
    if "shell" in s: fail("a step sets a shell")
uses = [s["uses"] for s in steps if "uses" in s]
if not uses or not all(re.fullmatch(r"[A-Za-z0-9._/-]+@[0-9a-f]{40}", u.split(" ")[0]) for u in uses): fail("an action is not a commit digest: " + str(uses))
co = [s for s in steps if s.get("uses", "").startswith("actions/checkout@")]
if not co or str((co[0].get("with") or {}).get("fetch-depth", "")) != "0": fail("checkout must fetch the whole history (fetch-depth: 0)")
if len(co) != 1 or steps.index(co[0]) != 0 or set(co[0].get("with") or {}) != {"fetch-depth"}: fail("the one checkout comes first and sets only fetch-depth (no ref, repository, path, token)")
import json
blob = json.dumps(job) + json.dumps(d.get("env")) + json.dumps(d.get("defaults"))
if re.search(r"GOSUMDB|GONOSUMDB|GONOSUMCHECK|GOPRIVATE|GOINSECURE|GOFLAGS|GOPROXY|-insecure|-mod=mod", blob): fail("a Go environment setting or opt-out in the vendor job or the workflow env")
if "continue-on-error" in blob or "continue-on-error" in str(d.get("defaults")): fail("continue-on-error in the vendor job")
PY
t AC3 "ci.yml vendor job: bare pull_request trigger, hosted runner, exactly go mod verify, bin/vendor-check.sh, then the provenance check, no condition, no opt-out, digest pins, history fetched" python3 "$J" "$root/.github/workflows/ci.yml"
mutate() { # NAME PYTHON-EXPRESSION on s (the ci.yml text): the mutated file must be refused
  python3 - "$root/.github/workflows/ci.yml" "$work/mut-$1.yml" "$2" <<'PY'
import sys
s = open(sys.argv[1]).read(); o = s
exec(sys.argv[3])
assert s != o, "mutation did not apply"
open(sys.argv[2], "w").write(s)
PY
  tn AC3 "the job check refuses: $1" python3 "$J" "$work/mut-$1.yml"
}
tn() { local ac=$1 d=$2; shift 2; if "$@" >"$work/out" 2>&1; then bad "$ac" "$d (expected a refusal)"; else ok; fi; }
mutate provenance-or-true 's = s.replace("--provenance dependency-provenance.json\n", "--provenance dependency-provenance.json || true\n", 1)'
mutate provenance-echo-only 's = s.replace("run: python3 bin/vendor-provenance.py check", "run: echo bin/vendor-provenance.py check", 1)'
mutate provenance-other-file 's = s.replace("--provenance dependency-provenance.json\n", "--provenance /dev/null\n", 1)'
mutate provenance-before-check 's = s.replace("        run: go mod verify\n      - name: vendor/ is what go mod vendor regenerates\n        run: bash bin/vendor-check.sh\n      - name: dependency-provenance.json lists the modules of vendor/ with the hashes of go.sum (REQ-VEND-001-AC4)\n        run: python3 bin/vendor-provenance.py check --vendor-dir vendor --go-sum go.sum --provenance dependency-provenance.json\n", "        run: go mod verify\n      - name: p\n        run: python3 bin/vendor-provenance.py check --vendor-dir vendor --go-sum go.sum --provenance dependency-provenance.json\n      - name: vendor/ is what go mod vendor regenerates\n        run: bash bin/vendor-check.sh\n", 1)'
mutate provenance-second-step 's = s.replace("        run: bash bin/vendor-check.sh\n", "        run: bash bin/vendor-check.sh\n      - name: extra\n        run: echo hi\n", 1)'
mutate trigger-branches 's = s.replace("  pull_request:\n", "  pull_request:\n    branches: [main]\n", 1)'
mutate or-true 's = s.replace("run: bash bin/vendor-check.sh\n", "run: bash bin/vendor-check.sh || true\n", 1)'
mutate echo-only 's = s.replace("run: bash bin/vendor-check.sh\n", "run: echo bin/vendor-check.sh\n", 1)'
mutate coe-expression 's = s.replace("  vendor:\n    name: vendor\n", "  vendor:\n    name: vendor\n    continue-on-error: ${{ true }}\n", 1)'
mutate job-if 's = s.replace("  vendor:\n    name: vendor\n", "  vendor:\n    name: vendor\n    if: github.actor != \x27dependabot[bot]\x27\n", 1)'
mutate step-if-always 's = s.replace("      - name: vendor/ is what go mod vendor regenerates\n", "      - name: vendor/ is what go mod vendor regenerates\n        if: ${{ !cancelled() && false }}\n", 1)'
mutate job-env-goflags 's = s.replace("  vendor:\n    name: vendor\n", "  vendor:\n    name: vendor\n    env:\n      GOFLAGS: -mod=mod\n", 1)'
mutate shell-override 's = s.replace("        run: bash bin/vendor-check.sh\n", "        shell: bash {0}\n        run: bash bin/vendor-check.sh\n", 1)'
mutate unpinned-action 's = s.replace("      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n        with:\n          go-version-file: go.mod", "      - uses: actions/setup-go@v7\n        with:\n          go-version-file: go.mod", 1)'
mutate defaults-shell 's = s.replace("jobs:\n", "defaults:\n  run:\n    shell: \x27bash -c \"exit 0\" {0}\x27\njobs:\n", 1)'
mutate job-renamed 's = s.replace("  vendor:\n    name: vendor\n", "  vendor:\n    name: vendor-skipped\n", 1)'
mutate checkout-ref 's = s.replace("          fetch-depth: 0\n", "          fetch-depth: 0\n          ref: main\n", 1)'
mutate checkout-repository 's = s.replace("          fetch-depth: 0\n", "          fetch-depth: 0\n          repository: o/r\n", 1)'
mutate env-shellopts 's = s.replace("jobs:\n", "env:\n  SHELLOPTS: noexec\njobs:\n", 1)'
mutate env-bash-env 's = s.replace("jobs:\n", "env:\n  BASH_ENV: /dev/null\njobs:\n", 1)'
mutate runner-private 's = s.replace("  vendor:\n    name: vendor\n    runs-on: ubuntu-latest\n", "  vendor:\n    name: vendor\n    runs-on: ubuntu-private\n", 1)'
mutate shallow-checkout 's = s.replace("        with:\n          fetch-depth: 0\n", "", 1)'

# ===== AC11: listable shape =======================================================================
f=bin/vendor-check.sh
t AC11 "$f has a shebang and mode 100755 in git" bash -c "[ -e '$f' ] && head -1 '$f' | grep -q '^#!' && git ls-files -s '$f' | grep -q '^100755'"
t AC11 "$f assigns none of PATH IFS BASH_ENV ENV LD_* PYTHON*" bash -c "[ -e '$f' ] && ! grep -Eq '(^|[^A-Za-z0-9_])(PATH|IFS|BASH_ENV|ENV|LD_[A-Za-z0-9_]*|PYTHON[A-Za-z0-9_]*)[+]?=' '$f'"
t AC11 "$f runs no python3 -c and no here-document interpreter" bash -c "[ -e '$f' ] && ! grep -Eq 'python3? +-c|python3? +-( |$)|<<' '$f'"
# the command-word judge reads the script as shell words (quotes, $( ), ${ } and backticks nest inside a word), skips assignment prefixes and
# the words after case/for, and flags any command word that holds an expansion
cat >"$work/cmdword.py" <<'CMDWORD_PY'
import re, sys
KW = {"then", "do", "else", "if", "elif", "while", "until", "time", "!", "{", "}", "case", "for", "select", "in", "esac", "fi", "done"}
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
OPS = ";&|(){}<>"
def lex(line):
    """words and operators of one line; quotes, $( ), ${ } and backticks nest inside a word"""
    i, n, toks = 0, len(line), []
    while i < n:
        c = line[i]
        if c.isspace():
            i += 1; continue
        if c == "#":
            break
        if c in OPS:
            j = i + 1
            while j < n and line[j] in OPS and line[j] == c and c in "&|;<>":
                j += 1
            toks.append(("op", line[i:j])); i = j; continue
        j, word = i, ""
        while j < n and not line[j].isspace() and line[j] not in OPS:
            ch = line[j]
            if ch in "'\"":
                k = j + 1
                while k < n and line[k] != ch:
                    if ch == '"' and line[k] == "\\": k += 1
                    k += 1
                j = k + 1; continue
            if ch == "`":
                k = line.find("`", j + 1); j = n if k < 0 else k + 1; continue
            if ch == "$" and line[j + 1:j + 2] in ("(", "{"):
                op, cl = ("(", ")") if line[j + 1] == "(" else ("{", "}")
                d, k = 1, j + 2
                while k < n and d:
                    d += line[k] == op; d -= line[k] == cl; k += 1
                j = k; continue
            if ch == "\\": j += 1
            j += 1
        toks.append(("word", line[i:j])); i = j
    return toks
def findings(text):
    out = []
    for n, raw in enumerate(text.split("\n"), 1):
        toks = lex(raw.strip())
        pos, skip = True, False
        for kind, t in toks:
            if skip:
                skip = False; continue
            if kind == "op":
                if t[0] in "<>":
                    skip = True
                else:
                    pos = True
                continue
            if pos and t in ("case", "for", "select"):
                pos = False; continue
            if pos and t in KW:
                continue
            if pos and ASSIGN.match(t):
                continue
            if pos:
                if "$" in t or "`" in t:
                    out.append((n, "command word built by expansion: " + t))
                pos = False
    return out
if __name__ == "__main__":
    fs = findings(sys.argv[2] if sys.argv[1] == "-c" else open(sys.argv[1]).read())
    for n, m in fs:
        print("%d: %s" % (n, m))
    sys.exit(1 if fs else 0)
CMDWORD_PY
for line in ':; $(printf true)' '$(printf true)' 'x && `date`' 'if a; then $cmd' 'cmd=a; $prog arg' '( $(echo x) )' 'e$(printf cho) >/dev/null' 'x && ec$(printf ho) a' 'p$cmd arg' 'cmd=a; pre${prog} arg' 'if $(printf true); then :; fi' 'while $(echo x); do :; done' 'if a; then :; elif $(printf x); then :; fi' 'until $x; do :; done' '! $(printf false)' 'GOAUTH=off g"$(printf o)" mod verify' "AUDIT_LABEL='two words' GOAUTH=off \"g\$(printf o)\" mod verify" 'AUDIT_LABEL="two words" GOAUTH=off "g$(printf o)" mod verify' 'A=b "$(printf go)" x' 'cmd=a; "$prog" arg' 'p"$cmd" arg' 'case $x in a) $(echo y);; esac'; do
  tn AC11 "the command-word judge flags: $line" python3 "$work/cmdword.py" -c "$line"
done
for line in 'found=$(find "$src" -print)' 'echo "$x"' 'cmp -s "$a" "$b" || die "x"' 'tree="$scratch/tree"' '[ "$(cd "$self/.." && pwd -P)" = "$(pwd -P)" ] || die x' 'cat "$a" >&2; die "go mod verify failed" 1' 'case $x in -*) die y;; esac' 'self=${0%/*}; [ "$self" != "$0" ] || self=.'; do
  t AC11 "the command-word judge leaves alone: $line" python3 "$work/cmdword.py" -c "$line"
done
t AC11 "$f builds no command word by substitution or variable" python3 "$work/cmdword.py" "$f"
rc AC11 "vendor-check.sh exits 2 outside the repository root" 2 bash -c "cd '$work' && bash '$bin_vc'"
# the root is the directory the script itself sits in, never a stand-in file of the same name
mkdir -p "$work/impostor/bin"; cp "$bin_vc" "$work/impostor/bin/vendor-check.sh"
rc AC11 "a copy of the script in a directory that is not its own root exits 2" 2 bash -c "cd '$work/impostor' && bash '$bin_vc' '$root'"
rc AC11 "run from the repository root by a relative path it still works (no vendor, no base: refused or passed, never 2 for the root)" 0 bash -c "cd '$work/g-absent' && mkdir -p bin && cp '$bin_vc' bin/vendor-check.sh && bash bin/vendor-check.sh"

echo "vendoring-test: $pass passed, $failn failed"
[ "$failn" = 0 ]
