#!/usr/bin/env bash
# proves: REQ-IMAGE-001-AC13
# Tests for bin/check-no-outbound.py (0710 item 4): fixture trees in a temporary folder, plus the real tree.
set -uo pipefail
cd "$(dirname "$0")/.."
CHK=bin/check-no-outbound.py
pass=0; fail=0
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
n=0
CLEAN="no HTTP client and no outbound dial"
BIN_CLEAN="holds no HTTP client symbol"
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
# case_ <expect-rc> <description> <text the output must hold> <file name under cmd/x or internal/x> <<go source>>
case_() {
  local want=$1 desc=$2 text=$3 name=$4 root
  n=$((n+1)); root="$tmp/t$n"; mkdir -p "$root/$(dirname "$name")"
  cat >"$root/$name"
  run_scan "$root"
  expect "$desc" "$want" "$text"
}
# tree_case <expect-rc> <description> <text the output must hold> <file name> <contents> [<file name> <contents> ...]
# the files of one package, each as printf %b text (so \n and \r can be written): for two files or a carriage return
tree_case() {
  local want=$1 desc=$2 text=$3 root
  shift 3; n=$((n+1)); root="$tmp/t$n"
  while [ $# -ge 2 ]; do
    mkdir -p "$root/$(dirname "$1")"; printf '%b' "$2" >"$root/$1"; shift 2
  done
  run_scan "$root"
  expect "$desc" "$want" "$text"
}
# every banned name has a case of its own, typed here: deleting one name from the checker turns its case red
refused() { # <import path> <name>
  local src; src=$(printf 'package y\n\nimport p "%s"\n\nvar _ = p.%s\n' "$1" "$2")
  case_ 1 "$1.$2 is refused" "uses $1.$2" internal/y/b.go <<<"$src"
}
refused_call() { # <name>: a call of this name on any value
  local src; src=$(printf 'package y\n\nfunc f(x any) { x.%s() }\n' "$1")
  case_ 1 "a call of $1 is refused" "calls $1" internal/y/b.go <<<"$src"
}
case_ 0 "a server using net/http and net.Listen is allowed" "$CLEAN" cmd/x/a.go <<'GO'
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
case_ 1 "http.Get is refused" "uses net/http.Get" cmd/x/a.go <<'GO'
package main

import "net/http"

func main() { http.Get("http://x") }
GO
case_ 1 "an aliased net/http Client is refused" "uses net/http.Client" internal/y/b.go <<'GO'
package y

import (
	h "net/http"
)

var c = &h.Client{}
GO
case_ 1 "http.NewRequestWithContext is refused" "uses net/http.NewRequestWithContext" internal/y/b.go <<'GO'
package y

import "net/http"

func f() { http.NewRequestWithContext(nil, "GET", "", nil) }
GO
case_ 1 "net.Dial is refused" "uses net.Dial" internal/y/b.go <<'GO'
package y

import "net"

func f() { net.Dial("tcp", "x:1") }
GO
case_ 1 "net.Dialer is refused" "uses net.Dialer" internal/y/b.go <<'GO'
package y

import "net"

var d net.Dialer
GO
case_ 1 "net.LookupHost is refused" "uses net.LookupHost" internal/y/b.go <<'GO'
package y

import "net"

func f() { net.LookupHost("x") }
GO
case_ 1 "tls.Dial is refused" "uses crypto/tls.Dial" internal/y/b.go <<'GO'
package y

import "crypto/tls"

func f() { tls.Dial("tcp", "x:1", nil) }
GO
case_ 1 "an import of net/http/httputil is refused" "imports net/http/httputil" internal/y/b.go <<'GO'
package y

import _ "net/http/httputil"
GO
case_ 1 "a dot import of net/http is refused" "dot import of net/http" internal/y/b.go <<'GO'
package y

import . "net/http"

var _ = Get
GO
case_ 1 "a single-line import with an alias is followed" "uses net/http.DefaultClient" internal/y/b.go <<'GO'
package y

import nh "net/http"

var _ = nh.DefaultClient
GO
case_ 0 "a banned name in a comment, a string and a raw string is not a use" "$CLEAN" internal/y/b.go <<'GO'
package y

import "net/http"

// http.Get(url) would be a client call
/* http.Client{} and net.Dial */
var s = "http.Get and net.Dial"
var r = `http.Client`
var _ = http.StatusOK
GO
case_ 0 "tls.Config and tls.Listen are allowed (serving, not dialling)" "$CLEAN" internal/y/b.go <<'GO'
package y

import "crypto/tls"

var _ = tls.Config{}
var _ = tls.Listen
GO
case_ 0 "without the import, a local value named http is ignored" "$CLEAN" internal/y/b.go <<'GO'
package y

type t struct{ Get int }

func f() { var http t; _ = http.Get }
GO
# -- the imports are read as Go reads them: a comment, a raw string or an escape cannot hide one (round 1, F1) --
case_ 1 "a ) inside a comment in the import block does not end the block" "uses net/http.Get" internal/y/b.go <<'GO'
package y

import (
	"fmt" // print (stdout)
	h "net/http"
)

var _ = fmt.Sprint
var _ = h.Get
GO
case_ 1 "a block comment between alias and path does not hide the import" "uses net/http.Get" internal/y/b.go <<'GO'
package y

import (
	/* ) */ h /* net/http is fetched here */ "net/http"
)

var _ = h.Get
GO
case_ 1 "an import path written as a raw string is read" "uses net/http.Get" internal/y/b.go <<'GO'
package y

import h `net/http`

var _ = h.Get
GO
case_ 1 "an import path written with a hex escape is read" "uses net/http.Get" internal/y/b.go <<'GO'
package y

import h "net/\x68ttp"

var _ = h.Get
GO
case_ 0 "an import written inside a comment is not an import" "$CLEAN" internal/y/b.go <<'GO'
package y

// import "net/http/httputil"
/* import h "net/http" */
var _ = 1
GO
case_ 1 "two imports on one line, separated by a semicolon, are both read" "uses net/http.Get" internal/y/b.go <<'GO'
package y

import ("fmt"; h "net/http")

var _ = fmt.Sprint
var _ = h.Get
GO

# -- our own code reaches no socket, runs no program and resolves no name (round 1, F2) --
case_ 1 "syscall.Socket is refused" "uses syscall.Socket" internal/y/b.go <<'GO'
package y

import "syscall"

func f() { syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0) }
GO
case_ 1 "syscall.Connect is refused" "uses syscall.Connect" internal/y/b.go <<'GO'
package y

import "syscall"

func f() { syscall.Connect(3, nil) }
GO
case_ 1 "unix.Connect is refused" "uses golang.org/x/sys/unix.Connect" internal/y/b.go <<'GO'
package y

import "golang.org/x/sys/unix"

func f() { unix.Connect(3, nil) }
GO
case_ 1 "an import of os/exec is refused" "imports os/exec" internal/y/b.go <<'GO'
package y

import "os/exec"

func f() { exec.Command("ls").Run() }
GO
case_ 1 "os.StartProcess is refused" "uses os.StartProcess" internal/y/b.go <<'GO'
package y

import "os"

func f() { os.StartProcess("/bin/ls", nil, nil) }
GO
case_ 1 "syscall.ForkExec is refused" "uses syscall.ForkExec" internal/y/b.go <<'GO'
package y

import "syscall"

func f() { syscall.ForkExec("/bin/ls", nil, nil) }
GO
# -- R2-2: a packet socket is refused outright, on any receiver, so a send in another file has nothing to send on --
for name in ListenPacket ListenUDP ListenMulticastUDP ListenIP; do refused_call "$name"; done
case_ 1 "a net.ListenConfig that listens for packets is refused" "calls ListenPacket" internal/y/b.go <<'GO'
package y

import (
	"context"
	"net"
)

func f() { var lc net.ListenConfig; lc.ListenPacket(context.Background(), "udp", ":0") }
GO
tree_case 1 "a UDP listen in one file and the send in another is refused" "calls ListenPacket" \
  internal/y/listen.go 'package y\n\nimport "net"\n\nfunc listen() { net.ListenPacket("udp", ":0") }\n' \
  internal/y/send.go 'package y\n\nimport "net"\n\nfunc send(c net.PacketConn, a net.Addr) { c.WriteTo(nil, a) }\n'
tree_case 1 "a ListenUDP in one file and WriteToUDP in another is refused" "calls ListenUDP" \
  internal/y/listen.go 'package y\n\nimport "net"\n\nfunc listen() { net.ListenUDP("udp", nil) }\n' \
  internal/y/send.go 'package y\n\nimport "net"\n\nfunc send(c *net.UDPConn, a *net.UDPAddr) { c.WriteToUDP(nil, a) }\n'
case_ 1 "net.ResolveUDPAddr is refused" "uses net.ResolveUDPAddr" internal/y/b.go <<'GO'
package y

import "net"

var _, _ = net.ResolveUDPAddr("udp", "x:1")
GO
case_ 1 "net.ResolveTCPAddr is refused" "uses net.ResolveTCPAddr" internal/y/b.go <<'GO'
package y

import "net"

var _, _ = net.ResolveTCPAddr("tcp", "x:1")
GO
case_ 0 "syscall for errno and Statfs is allowed" "$CLEAN" internal/y/b.go <<'GO'
package y

import "syscall"

func f() error {
	var st syscall.Statfs_t
	return syscall.Statfs("/", &st)
}
GO
case_ 0 "WriteTo on a value that is not a UDP socket is allowed" "$CLEAN" internal/y/b.go <<'GO'
package y

import (
	"bytes"
	"io"
)

func f(w io.Writer) { var b bytes.Buffer; b.WriteTo(w) }
GO

# -- our own code verifies no certificate and makes no TLS client (round 1, F3) --
case_ 1 "x509.SystemCertPool is refused" "uses crypto/x509.SystemCertPool" internal/y/b.go <<'GO'
package y

import "crypto/x509"

var _, _ = x509.SystemCertPool()
GO
case_ 1 "a Verify call in a file that imports crypto/x509 is refused" "crypto/x509 and Verify" \
  internal/y/b.go <<'GO'
package y

import (
	"crypto/x509"

	"example.com/dep"
)

func f(c *x509.Certificate) { c.Verify(dep.Options()) }
GO
case_ 1 "tls.Client is refused" "uses crypto/tls.Client" internal/y/b.go <<'GO'
package y

import (
	"crypto/tls"
	"net"
)

func f(c net.Conn) { tls.Client(c, &tls.Config{}) }
GO
case_ 1 "tls.Dialer is refused" "uses crypto/tls.Dialer" internal/y/b.go <<'GO'
package y

import "crypto/tls"

var d tls.Dialer
GO
case_ 1 "tls.DialWithDialer is refused" "uses crypto/tls.DialWithDialer" internal/y/b.go <<'GO'
package y

import "crypto/tls"

var _ = tls.DialWithDialer
GO
tree_case 1 "VerifyOptions built in one file and Verify called in another is refused" "uses crypto/x509.VerifyOptions" \
  internal/y/cert.go 'package y\n\nimport "crypto/x509"\n\nfunc opts() any { return x509.VerifyOptions{} }\n' \
  internal/y/check.go 'package y\n\nfunc check(c interface{ Verify(any) error }) error { return c.Verify(opts()) }\n'

# -- R2-4: our code never asks for a client certificate (the server would verify it against system roots) --
case_ 1 "ClientAuth set by constant is refused" "uses ClientAuth" internal/y/b.go <<'GO'
package y

import "crypto/tls"

var _ = tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}
GO
case_ 1 "ClientAuth set by number is refused" "uses ClientAuth" internal/y/b.go <<'GO'
package y

import "crypto/tls"

var _ = tls.Config{ClientAuth: 4}
GO
case_ 1 "ClientAuth set on a config value is refused" "uses ClientAuth" internal/y/b.go <<'GO'
package y

import "crypto/tls"

func f(c *tls.Config) { c.ClientAuth = 4 }
GO

# -- R2-1: Go drops a carriage return inside a raw string, so the import below is net --
tree_case 1 "a raw-string import path with a carriage return inside is read as Go reads it" "uses net.Dialer" \
  internal/y/b.go 'package y\n\nimport h `n\ret`\n\nvar _ h.Dialer\n'

# -- one case per banned name (R2-5, R2-6) --
for name in Client DefaultClient Transport DefaultTransport Get Head Post PostForm NewRequest \
            NewRequestWithContext; do refused net/http "$name"; done
for name in Dial DialTimeout DialTCP DialUDP DialIP DialUnix Dialer LookupAddr LookupCNAME LookupHost LookupIP \
            LookupMX LookupNS LookupPort LookupSRV LookupTXT Resolver DefaultResolver \
            ResolveIPAddr ResolveTCPAddr ResolveUDPAddr; do refused net "$name"; done
for name in Client Dial DialWithDialer Dialer; do refused crypto/tls "$name"; done
for name in SystemCertPool VerifyOptions; do refused crypto/x509 "$name"; done
for name in Connect Exec ForkExec Socket StartProcess Syscall Syscall6 RawSyscall RawSyscall6; do
  refused syscall "$name"
done
for name in Connect Exec Socket Syscall Syscall6 RawSyscall RawSyscall6; do refused golang.org/x/sys/unix "$name"; done
refused os StartProcess
case_ 0 "x509 parsing, with no Verify, is allowed" "$CLEAN" internal/y/b.go <<'GO'
package y

import "crypto/x509"

var _, _ = x509.ParseCertificate(nil)
GO
n=$((n+1)); root="$tmp/t$n"; mkdir -p "$root/cmd/x" "$root/internal/vendor/z"
printf 'package main\nimport "net/http"\nfunc f(){ http.Get("x") }\n' >"$root/cmd/x/a_test.go"
printf 'package z\nimport "net/http"\nfunc f(){ http.Get("x") }\n' >"$root/internal/vendor/z/z.go"
printf 'package main\nfunc main(){}\n' >"$root/cmd/x/a.go"
run_scan "$root";      expect "test files and vendor/ are not read" 0 "$CLEAN"
n=$((n+1)); root="$tmp/t$n"; mkdir -p "$root"
run_scan "$root";      expect "a tree with no Go files exits 2" 2 "no Go files"
run_scan;              expect "the real tree has no HTTP client and no outbound dial" 0 "$CLEAN"

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
    local want=$1 desc=$2 text=$3 dir
    n=$((n+1)); dir="$tmp/b$n"
    if ! build_main "$dir"; then
      echo "FAIL: $desc (fixture does not build: $(head -c 200 "$dir/build.err"))"; fail=$((fail+1)); return
    fi
    run_binary "$dir/prog"
    expect "$desc" "$want" "$text"
  }
  bin_case 0 "a server that only listens is allowed" "$BIN_CLEAN" <<'GO'
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
  bin_case 0 "RESIDUAL: a dial through net.Dialer alone is not caught by the binary check" "$BIN_CLEAN" <<'GO'
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
  # a symbol is listed only where a program here holds it and the clean server and the real binaries do not
  bin_case 1 "a TLS dialer" 'crypto/tls.(*Dialer).DialContext' <<'GO'
package main

import (
	"context"
	"crypto/tls"
)

func main() { (&tls.Dialer{}).DialContext(context.Background(), "tcp", "x:443") }
GO
  bin_case 1 "running a program (os/exec)" 'os/exec.(*Cmd).Start' <<'GO'
package main

import "os/exec"

func main() { exec.Command("ls").Run() }
GO
  bin_case 1 "net.ResolveTCPAddr" 'net.ResolveTCPAddr' <<'GO'
package main

import "net"

func main() { net.ResolveTCPAddr("tcp", "x:1") }
GO
  bin_case 1 "net.ResolveUDPAddr" 'net.ResolveUDPAddr' <<'GO'
package main

import "net"

func main() { net.ResolveUDPAddr("udp", "x:1") }
GO
  bin_case 1 "net.ResolveIPAddr" 'net.ResolveIPAddr' <<'GO'
package main

import "net"

func main() { net.ResolveIPAddr("ip", "x") }
GO
  # the residuals, written down as tests: a plain net/http server already holds these symbols, so none can be listed
  bin_case 0 "RESIDUAL: a TLS client handshake (tls.Client) is not caught by the binary check" "$BIN_CLEAN" <<'GO'
package main

import (
	"crypto/tls"
	"net"
)

func main() {
	c, _ := net.Pipe()
	tls.Client(c, &tls.Config{}).Handshake()
}
GO
  bin_case 0 "RESIDUAL: syscall.Socket and syscall.Connect are not caught by the binary check" "$BIN_CLEAN" <<'GO'
package main

import "syscall"

func main() {
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	syscall.Connect(fd, &syscall.SockaddrInet4{Port: 1})
}
GO
  # round 1, F4: the images ship for arm64 too; go tool nm reads the other architecture's binary
  GOARCH=arm64 bin_case 1 "an arm64 build of http.Get is refused too" 'net/http.(*Client).do' <<'GO'
package main

import "net/http"

func main() { http.Get("http://x") }
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
  run_binary "$tmp/text-file";           expect "a file that is not a Go program is refused" 2 "go tool nm failed"
  run_binary "$tmp/no-such-binary";      expect "a binary that does not exist is refused" 2 "cannot read"
  run_binary;                            expect "binary without a path is refused" 2 "usage"
  out=$(PATH=/nonexistent "$(command -v python3)" -I "$CHK" binary "$tmp/text-file" 2>&1); rc=$?
  expect "with no go on the search path the check exits 2 and never passes unchecked" 2 "go is not installed"
  # real_case <description> <GOARCH> <GOFIPS140 value, empty for the plain build>: builds ./cmd/fscache like the recipes
  real_case() {
    local desc=$1 arch=$2 fips=$3 bin="$tmp/fscache-$2${3:+-fips}"
    if ! GOARCH=$arch GOFIPS140=$fips GOFLAGS=-mod=vendor gobuild -o "$bin" ./cmd/fscache 2>"$tmp/real.err"; then
      echo "FAIL: $desc does not build: $(head -c 300 "$tmp/real.err")"; fail=$((fail+1)); return
    fi
    run_binary "$bin"
    expect "$desc has no HTTP client symbol and no dial symbol" 0 "$BIN_CLEAN"
    out=$(go version -m "$bin" | grep GOFIPS140); rc=$?
    if [ -n "$fips" ]; then
      expect "$desc was built with GOFIPS140=$fips_module" 0 "GOFIPS140=$fips_module"
    else
      expect "$desc was built without GOFIPS140" 1 -
    fi
  }
  # the FIPS recipe builds with the module version without its hash suffix; the build info records it with the suffix
  fips_module=$(cat build/locks/fips-module.txt)
  fips_version=${fips_module%%-*}
  for arch in amd64 arm64; do
    real_case "the plain $arch binary" "$arch" ""
    real_case "the FIPS $arch binary" "$arch" "$fips_version"
  done
fi
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
