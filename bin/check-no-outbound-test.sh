#!/usr/bin/env bash
# proves: REQ-IMAGE-001-AC13
# Tests for bin/check-no-outbound.py (0710 item 4): fixture trees in a temporary folder, plus the real tree.
set -uo pipefail
cd "$(dirname "$0")/.."
CHK=bin/check-no-outbound.py
pass=0; fail=0
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
n=0
run_scan() { out=$(python3 -I "$CHK" "$@" 2>&1); rc=$?; }
# expect <description> <wanted exit code> <text the output must hold, or ->
expect() {
  local desc=$1 want=$2 text=$3
  if [ "$rc" = "$want" ] && { [ "$text" = - ] || printf '%s' "$out" | grep -qF -- "$text"; }; then
    echo "ok:   $desc"; pass=$((pass+1))
  else
    echo "FAIL: $desc (exit $rc, wanted $want, text '$text'): $out"; fail=$((fail+1))
  fi
}
# case <expect-rc> <description> <file name under cmd/x or internal/x> <<go source>>
case_() {
  local want=$1 desc=$2 name=$3 root
  n=$((n+1)); root="$tmp/t$n"; mkdir -p "$root/$(dirname "$name")"
  cat >"$root/$name"
  run_scan "$root"
  expect "$desc" "$want" -
}
case_ 0 "a server using net/http and net.Listen is allowed" cmd/x/a.go <<'GO'
package main

import (
	"net"
	"net/http"
)

func main() {
	l, _ := net.Listen("tcp", ":8080")
	http.Serve(l, http.NewServeMux())
	_ = http.StatusOK
}
GO
case_ 1 "http.Get is refused" cmd/x/a.go <<'GO'
package main

import "net/http"

func main() { http.Get("http://x") }
GO
case_ 1 "an aliased net/http Client is refused" internal/y/b.go <<'GO'
package y

import (
	h "net/http"
)

var c = &h.Client{}
GO
case_ 1 "http.NewRequestWithContext is refused" internal/y/b.go <<'GO'
package y

import "net/http"

func f() { http.NewRequestWithContext(nil, "GET", "", nil) }
GO
case_ 1 "net.Dial is refused" internal/y/b.go <<'GO'
package y

import "net"

func f() { net.Dial("tcp", "x:1") }
GO
case_ 1 "net.Dialer is refused" internal/y/b.go <<'GO'
package y

import "net"

var d net.Dialer
GO
case_ 1 "net.LookupHost is refused" internal/y/b.go <<'GO'
package y

import "net"

func f() { net.LookupHost("x") }
GO
case_ 1 "tls.Dial is refused" internal/y/b.go <<'GO'
package y

import "crypto/tls"

func f() { tls.Dial("tcp", "x:1", nil) }
GO
case_ 1 "an import of net/http/httputil is refused" internal/y/b.go <<'GO'
package y

import _ "net/http/httputil"
GO
case_ 1 "a dot import of net/http is refused" internal/y/b.go <<'GO'
package y

import . "net/http"

var _ = Get
GO
case_ 1 "a single-line import with an alias is followed" internal/y/b.go <<'GO'
package y

import nh "net/http"

var _ = nh.DefaultClient
GO
case_ 0 "a banned name in a comment, a string and a raw string is not a use" internal/y/b.go <<'GO'
package y

import "net/http"

// http.Get(url) would be a client call
/* http.Client{} and net.Dial */
var s = "http.Get and net.Dial"
var r = `http.Client`
var _ = http.StatusOK
GO
case_ 0 "tls.Config and tls.Listen are allowed (serving, not dialling)" internal/y/b.go <<'GO'
package y

import "crypto/tls"

var _ = tls.Config{}
var _ = tls.Listen
GO
case_ 0 "without the import, a local value named http is ignored" internal/y/b.go <<'GO'
package y

type t struct{ Get int }

func f() { var http t; _ = http.Get }
GO
n=$((n+1)); root="$tmp/t$n"; mkdir -p "$root/cmd/x" "$root/internal/vendor/z"
printf 'package main\nimport "net/http"\nfunc f(){ http.Get("x") }\n' >"$root/cmd/x/a_test.go"
printf 'package z\nimport "net/http"\nfunc f(){ http.Get("x") }\n' >"$root/internal/vendor/z/z.go"
printf 'package main\nfunc main(){}\n' >"$root/cmd/x/a.go"
run_scan "$root";      expect "test files and vendor/ are not read" 0 -
n=$((n+1)); root="$tmp/t$n"; mkdir -p "$root"
run_scan "$root";      expect "a tree with no Go files exits 2" 2 -
run_scan;              expect "the real tree has no HTTP client and no outbound dial" 0 -

# -- the built binary (REQ-IMAGE-001-AC13): `go tool nm` is the call graph, the linker drops what main cannot reach --
# Each refused symbol has a program here that uses it. A missing go skips locally and fails in CI.
run_binary() { run_scan binary "$@"; }
if ! command -v go >/dev/null 2>&1; then
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "FAIL: go is not installed on this runner, the binary check cannot run"; fail=$((fail+1))
  else
    echo "skip: needs go (the binary checks)"
  fi
else
  # the flags of build/melange.yaml: -trimpath, CGO_ENABLED=0, and nothing that strips the symbol table
  gobuild() { GOPROXY=off CGO_ENABLED=0 go build -trimpath "$@"; }
  # build_main <dir> [extra go build flags]: the main package on stdin becomes <dir>/prog
  build_main() {
    local dir=$1; shift
    mkdir -p "$dir"; printf 'module fx\ngo 1.22\n' >"$dir/go.mod"; cat >"$dir/main.go"
    (cd "$dir" && gobuild "$@" -o prog . 2>"$dir/build.err")
  }
  # bin_case <exit code> <description> <symbol the output must name, or -> <<go source>>
  bin_case() {
    local want=$1 desc=$2 text=$3 dir="$tmp/b$((n+=1))"
    if ! build_main "$dir"; then
      echo "FAIL: $desc (fixture does not build: $(head -c 200 "$dir/build.err"))"; fail=$((fail+1)); return
    fi
    run_binary "$dir/prog"
    expect "$desc" "$want" "$text"
  }
  bin_case 0 "a server that only listens is allowed" - <<'GO'
package main

import (
	"net"
	"net/http"
)

func main() {
	l, _ := net.Listen("tcp", ":0")
	http.Serve(l, http.NewServeMux())
}
GO
  bin_case 1 "http.Get puts net/http.(*Client).do in the binary" 'net/http.(*Client).do' <<'GO'
package main

import "net/http"

func main() { http.Get("http://x") }
GO
  bin_case 1 "a Transport used directly puts roundTrip in the binary" 'net/http.(*Transport).roundTrip' <<'GO'
package main

import "net/http"

func main() {
	req, _ := http.NewRequest("GET", "http://x", nil)
	(&http.Transport{}).RoundTrip(req)
}
GO
  bin_case 1 "net.Dial" 'net.Dial' <<'GO'
package main

import "net"

func main() { net.Dial("tcp", "x:1") }
GO
  bin_case 1 "net.DialTimeout" 'net.DialTimeout' <<'GO'
package main

import (
	"net"
	"time"
)

func main() { net.DialTimeout("tcp", "x:1", time.Second) }
GO
  bin_case 1 "a name lookup (net.(*Resolver).LookupHost)" 'net.(*Resolver).LookupHost' <<'GO'
package main

import "net"

func main() { net.LookupHost("x") }
GO
  bin_case 1 "tls.Dial" 'crypto/tls.Dial' <<'GO'
package main

import "crypto/tls"

func main() { tls.Dial("tcp", "x:443", nil) }
GO
  # the residual, written down as a test: net.(*Dialer).DialContext is in every net/http binary, so it is no evidence
  bin_case 0 "RESIDUAL: a dial through net.Dialer alone is not caught by the binary check" - <<'GO'
package main

import (
	"context"
	"net"
)

func main() {
	var d net.Dialer
	d.DialContext(context.Background(), "tcp", "x:1")
}
GO
  # fail closed: with no symbol table `go tool nm` lists nothing, and "nothing found" must not read as "clean"
  stripped="$tmp/stripped"
  build_main "$stripped" -ldflags=-s <<'GO'
package main

import "net/http"

func main() { http.Get("http://x") }
GO
  run_binary "$stripped/prog"
  expect "a stripped binary, even one with an HTTP client, is refused" 2 "symbol"
  # a `go tool nm` that exits 0 with an empty list is no proof either (every Go program holds runtime.main)
  mkdir -p "$tmp/fakego"; printf '#!/bin/sh\nexit 0\n' >"$tmp/fakego/go"; chmod +x "$tmp/fakego/go"
  out=$(PATH="$tmp/fakego:$PATH" python3 -I "$CHK" binary "$stripped/prog" 2>&1); rc=$?
  expect "an empty symbol list with exit 0 is refused" 2 "runtime.main"
  printf 'not a program\n' >"$tmp/text-file"
  run_binary "$tmp/text-file";           expect "a file that is not a Go program is refused" 2 -
  run_binary "$tmp/no-such-binary";      expect "a binary that does not exist is refused" 2 "cannot read"
  run_binary;                            expect "binary without a path is refused" 2 "usage"
  out=$(PATH=/nonexistent "$(command -v python3)" -I "$CHK" binary "$tmp/text-file" 2>&1); rc=$?
  expect "with no go on the search path the check exits 2 and never passes unchecked" 2 "go is not installed"
  real="$tmp/fscache"
  if GOFLAGS=-mod=vendor gobuild -o "$real" ./cmd/fscache 2>"$tmp/real.err"; then
    run_binary "$real"
    expect "the real fscache binary has no HTTP client symbol and no dial symbol" 0 -
  else
    echo "FAIL: the real binary does not build: $(head -c 300 "$tmp/real.err")"; fail=$((fail+1))
  fi
fi
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
