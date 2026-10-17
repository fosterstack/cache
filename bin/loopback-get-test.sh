#!/usr/bin/env bash
# proves: REQ-SUP-001-AC24
# bin/loopback-get.sh (advisor reading, Oct 17): the only way a script reaches a local or in-cluster address. It refuses every URL that is not
# http://localhost, http://127.0.0.1 (any port), the in-cluster service name `fscache`, or the runner's own token endpoint; it allows a closed list of
# curl options; it never follows a redirect, never uses a proxy, never speaks https to a loopback name. A stub `curl` on PATH records the call.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
H="$root/bin/loopback-get.sh"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cat > "$work/bin/curl" <<'STUB'
#!/bin/sh
printf '%s\n' "$@" > "$STUB_OUT"
echo "stub-curl-ran"
STUB
chmod +x "$work/bin/curl"
export PATH="$work/bin:$PATH" STUB_OUT="$work/args"
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
[ -f "$H" ] || { bad "bin/loopback-get.sh exists"; echo "loopback-get: $pass passed, $failn failed"; exit 1; }
allowed() {   # allowed NAME ARGS...: the helper runs curl
  local name="$1"; shift; rm -f "$STUB_OUT"
  out=$(env -u ACTIONS_ID_TOKEN_REQUEST_URL sh "$H" "$@" 2>&1); rc=$?
  if [ "$rc" = 0 ] && [ -f "$STUB_OUT" ] && [ "$out" = "stub-curl-ran" ]; then ok "allowed: $name"; else bad "allowed: $name (rc=$rc out=$out)"; fi
}
refused() {   # refused NAME ARGS...: nonzero, curl never ran
  local name="$1"; shift; rm -f "$STUB_OUT"
  out=$(env -u ACTIONS_ID_TOKEN_REQUEST_URL sh "$H" "$@" 2>&1); rc=$?
  if [ "$rc" != 0 ] && [ ! -f "$STUB_OUT" ]; then ok "refused: $name"; else bad "refused: $name (rc=$rc ran=$([ -f "$STUB_OUT" ] && echo yes || echo no))"; fi
}
# --- the addresses the scripts use
allowed "localhost with a port and no scheme (the Gradle suite)" -s localhost:18096/metrics
allowed "localhost with http and a port" -s http://localhost:18099/maven/oversizedprobe
allowed "127.0.0.1 with a port" -sf --max-time 2 http://127.0.0.1:8080/healthz
allowed "127.0.0.1 without a port" -sf http://127.0.0.1/statusz
allowed "the in-cluster service name" -sf http://fscache/runnerkey123
allowed "the service name with a port" -sf http://fscache:8080/k
allowed "a bare host and port, nothing after" -sf localhost:18095
allowed "a PUT with a body and credentials" -sf -u "user:pa ss" -X PUT --data-binary payload http://fscache/k -o /dev/null
allowed "-I, -D and -w" -s -D - -o /dev/null -w '%{http_code}' -I localhost:18096/x
allowed "combined short flags" -sSf http://127.0.0.1:9/x
allowed "a header" -sf -H "Accept: text/plain" http://localhost:1/x
# --- the other URLs
refused "a remote host" -s http://example.com/x
refused "a remote host with https" -s https://example.com/x
refused "https to a loopback name (the helper speaks http only)" -s https://localhost:18096/x
refused "a lookalike suffix" -s http://localhost.evil.example/x
refused "a lookalike prefix" -s http://evillocalhost/x
refused "127.0.0.1 as a prefix of a longer name" -s http://127.0.0.1.evil.example/x
refused "127.0.0.10" -s http://127.0.0.10/x
refused "userinfo naming a remote host" -s http://localhost@evil.example/x
refused "userinfo with a loopback name first" -s http://localhost:80@evil.example/x
refused "userinfo before a loopback host" -s http://evil.example@localhost/x
refused "a bare host with userinfo" -s localhost@evil.example/x
refused "a port that is not digits" -s http://localhost:80a/x
refused "an empty port" -s http://localhost:/x
refused "IPv6 loopback (not in the list)" -s "http://[::1]/x"
refused "a URL with whitespace" -s "http://localhost/x y"
refused "a URL with a fragment host trick" -s "http://localhost#@evil.example/"
refused "a backslash host trick" -s 'http://localhost\@evil.example/'
refused "no URL at all" -s
refused "two URLs, the second remote" -s http://localhost/x http://example.com/y
refused "two URLs, the first remote" -s http://example.com/y http://localhost/x
refused "a URL given by --url" -s --url http://example.com/x http://localhost/y
refused "a file URL" -s file:///etc/passwd
refused "an ftp URL" -s ftp://localhost/x
refused "an uppercase scheme trick" -s HTTP://example.com/x
# --- options
refused "-L (follow redirects)" -sL http://localhost/x
refused "--location" -s --location http://localhost/x
refused "-K (a config file can hold a URL)" -K /tmp/x http://localhost/x
refused "--config" -s --config /tmp/x http://localhost/x
refused "-x (a proxy)" -s -x http://example.com:3128 http://localhost/x
refused "--resolve" -s --resolve localhost:80:93.184.216.34 http://localhost/x
refused "--connect-to" -s --connect-to localhost:80:example.com:80 http://localhost/x
refused "-X with another method" -s -X DELETE http://localhost/x
refused "-T (upload a file)" -s -T /etc/passwd http://localhost/x
refused "--next" -s --next http://example.com/x
refused "an unknown option" -s --frobnicate http://localhost/x
refused "-o with no value" -s http://localhost/x -o
refused "--max-time with a non-number" -s --max-time abc http://localhost/x
# --- what the helper passes to curl
rm -f "$STUB_OUT"; env -u ACTIONS_ID_TOKEN_REQUEST_URL sh "$H" -s -u mvn:acceptance-secret localhost:18098/metrics > /dev/null 2>&1
a=$(cat "$STUB_OUT" 2>/dev/null | tr '\n' ' ')
case "$a" in *"-q "*) ok "curl is started with -q (no .curlrc)";; *) bad "curl is started with -q: $a";; esac
case "$a" in *"--noproxy * "*) ok "no proxy is used";; *) bad "no proxy: $a";; esac
case "$a" in *"--proto =http "*) ok "only the http protocol is allowed";; *) bad "--proto =http: $a";; esac
case "$a" in *"--max-redirs 0 "*) ok "no redirect is followed";; *) bad "--max-redirs 0: $a";; esac
case "$a" in *"-u mvn:acceptance-secret "*"http://localhost:18098/metrics"*) ok "the options and the URL are passed through; a bare host:port gets http://";; *) bad "pass-through: $a";; esac
# --- the runner's token endpoint
tok() {   # tok NAME URLENV ARGS...
  local name="$1" u="$2"; shift 2; rm -f "$STUB_OUT"
  out=$(ACTIONS_ID_TOKEN_REQUEST_URL="$u" sh "$H" "$@" 2>&1); rc=$?
  RC=$rc
}
TU="https://pipelines.actions.example.invalid/_apis/token?x=1"
tok t "$TU" -sSf -H "Authorization: bearer abc" "${TU}&audience=sigstore"
if [ "$RC" = 0 ] && [ -f "$STUB_OUT" ]; then ok "allowed: the runner's token URL plus an audience"; else bad "token URL plus audience (rc=$RC $out)"; fi
case "$(tr '\n' ' ' < "$STUB_OUT")" in *"--proto =https "*) ok "the token request is https only";; *) bad "token request protocol";; esac
tok t "$TU" -sSf "${TU}&audience=https://api.anthropic.com"
if [ "$RC" = 0 ] && [ -f "$STUB_OUT" ]; then ok "allowed: a token request with a URL-shaped audience"; else bad "token audience URL (rc=$RC $out)"; fi
tok t "$TU" -sSf "$TU"
if [ "$RC" = 0 ] && [ -f "$STUB_OUT" ]; then ok "allowed: the token URL itself"; else bad "token URL alone (rc=$RC $out)"; fi
tok t "$TU" -sSf "https://example.com/_apis/token?x=1&audience=sigstore"
if [ "$RC" != 0 ] && [ ! -f "$STUB_OUT" ]; then ok "refused: another host when the token variable is set"; else bad "another host with token variable (rc=$RC)"; fi
tok t "$TU" -sSf "${TU}x&audience=sigstore"
if [ "$RC" != 0 ] && [ ! -f "$STUB_OUT" ]; then ok "refused: the token URL with something glued on before the audience"; else bad "glued token URL (rc=$RC)"; fi
tok t "" -sSf "&audience=sigstore"
if [ "$RC" != 0 ] && [ ! -f "$STUB_OUT" ]; then ok "refused: an empty token variable"; else bad "empty token variable (rc=$RC)"; fi
tok t "http://example.com/t" -sSf "http://example.com/t&audience=sigstore"
if [ "$RC" != 0 ] && [ ! -f "$STUB_OUT" ]; then ok "refused: a token endpoint that is not https"; else bad "http token endpoint (rc=$RC)"; fi
tok t "$TU" -sSf "${TU}&audience=sigstore" http://example.com/x
if [ "$RC" != 0 ] && [ ! -f "$STUB_OUT" ]; then ok "refused: the token URL beside a second URL"; else bad "token plus second URL (rc=$RC)"; fi
# --- the call sites no longer name curl
for f in acceptance-gradle.sh acceptance-gradle-capped.sh acceptance-maven.sh acceptance-maven-capped.sh acceptance-serve.sh acceptance-k8s.sh acceptance-egress.sh check-artifacts.sh check-fips.sh; do
  n=$(grep -v '^[[:space:]]*#' "$root/bin/$f" | grep -c '\bcurl\b' || true)
  case "$f" in
    acceptance-egress.sh) lim=2;;    # the strace download (the pinned fetch of the production PR) is the only curl left in the egress script
    acceptance-k8s.sh) lim=1;;      # the digest-pinned client image name (curlimages/curl) is the only curl left
    *) lim=0;;
  esac
  if [ "$n" -le "$lim" ]; then ok "bin/$f has no curl outside the loopback helper ($n)"; else bad "bin/$f still names curl $n time(s)"; fi
  grep -q 'loopback-get.sh' "$root/bin/$f" && ok "bin/$f calls the helper" || bad "bin/$f does not call the helper"
done
echo "loopback-get: $pass passed, $failn failed"
[ "$failn" = 0 ]
