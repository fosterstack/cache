#!/usr/bin/env bash
# proves: REQ-IMAGE-001-AC15
# Tests for bin/check-no-outbound.py (0710 item 4): fixture trees in a temporary folder, plus the real tree.
set -uo pipefail
cd "$(dirname "$0")/.."
CHK=bin/check-no-outbound.py
pass=0; fail=0
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
n=0
# case <expect-rc> <description> <file name under cmd/x or internal/x> <<go source>>
case_() {
  local want=$1 desc=$2 name=$3 root rc out
  n=$((n+1)); root="$tmp/t$n"; mkdir -p "$root/$(dirname "$name")"
  cat >"$root/$name"
  out=$(python3 -I "$CHK" "$root" 2>&1); rc=$?
  if [ "$rc" = "$want" ]; then echo "ok:   $desc"; pass=$((pass+1)); else echo "FAIL: $desc (rc $rc, wanted $want): $out"; fail=$((fail+1)); fi
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
if python3 -I "$CHK" "$root" >/dev/null 2>&1; then echo "ok:   test files and vendor/ are not read"; pass=$((pass+1)); else echo "FAIL: test files and vendor/ are not read"; fail=$((fail+1)); fi
n=$((n+1)); root="$tmp/t$n"; mkdir -p "$root"
python3 -I "$CHK" "$root" >/dev/null 2>&1; rc=$?
if [ "$rc" = 2 ]; then echo "ok:   a tree with no Go files exits 2"; pass=$((pass+1)); else echo "FAIL: a tree with no Go files exits 2 (rc $rc)"; fail=$((fail+1)); fi
out=$(python3 -I "$CHK" 2>&1); rc=$?
if [ "$rc" = 0 ]; then echo "ok:   the real tree has no HTTP client and no outbound dial"; pass=$((pass+1)); else echo "FAIL: the real tree: $out"; fail=$((fail+1)); fi
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
