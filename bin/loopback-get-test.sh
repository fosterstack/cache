#!/usr/bin/env bash
# proves: REQ-SUP-001-AC24
# bin/loopback-get.sh (advisor reading, Oct 17): the only way a script reaches a local or in-cluster address. It refuses every URL that is not
# http://localhost, http://127.0.0.1 (any port), the in-cluster service name `fscache`, or the runner's own token endpoint; it allows a closed list of
# curl options; it never follows a redirect, never uses a proxy, never speaks https to a loopback name. A stub `curl` on PATH records the call.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
H="$root/bin/loopback-get.sh"
# the program name the helper starts: the stub on PATH takes this name
STUBNAME=curl
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
cat > "$work/bin/$STUBNAME" <<'STUB'
#!/bin/sh
printf '%s\n' "$@" > "$STUB_OUT"
echo "stub-ran"
STUB
chmod +x "$work/bin/$STUBNAME"
export PATH="$work/bin:$PATH" STUB_OUT="$work/args"
pass=0 failn=0
ok()  { pass=$((pass + 1)); echo "ok   $1"; }
bad() { failn=$((failn + 1)); echo "FAIL $1"; }
[ -f "$H" ] || { bad "bin/loopback-get.sh exists"; # the helper function is defined where every step function sees it: at the top level, before the first function whose body is a subshell
for f in acceptance-serve.sh acceptance-egress.sh check-artifacts.sh check-fips.sh; do
  d=$(grep -n '^lg\(in\)\?() ' "$root/bin/$f" | head -1 | cut -d: -f1)
  fn=$(grep -n '^[a-z_0-9]*() *(' "$root/bin/$f" | head -1 | cut -d: -f1)
  if [ -n "$d" ] && { [ -z "$fn" ] || [ "$d" -lt "$fn" ]; }; then ok "bin/$f defines its loopback function at the top level"; else bad "bin/$f defines its loopback function inside a step (line ${d:-none}, first step line ${fn:-none})"; fi
done
echo "loopback-get: $pass passed, $failn failed"; exit 1; }
allowed() {   # allowed NAME ARGS...: the helper starts the fetch program
  local name="$1"; shift; rm -f "$STUB_OUT"
  out=$(env -u ACTIONS_ID_TOKEN_REQUEST_URL sh "$H" "$@" 2>&1); rc=$?
  if [ "$rc" = 0 ] && [ -f "$STUB_OUT" ] && [ "$out" = "stub-ran" ]; then ok "allowed: $name"; else bad "allowed: $name (rc=$rc out=$out)"; fi
}
refused() {   # refused NAME ARGS...: nonzero, the fetch program never ran
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
allowed "a path of just a slash" -sf localhost:18095/
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
refused "a bare host and port with no path" -sf localhost:18095
refused "a host with no path" -s http://localhost
refused "a fragment after a path" -s "http://localhost/healthz#fragment"
refused "a question mark and then a fragment" -s "http://localhost/x?a=1#b"
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
refused "--max-time 1..2" -s --max-time 1..2 http://localhost/x
refused "--max-time just a dot" -s --max-time . http://localhost/x
refused "--connect-timeout 1.2.3" -s --connect-timeout 1.2.3 http://localhost/x
refused "--connect-timeout .5" -s --connect-timeout .5 http://localhost/x
allowed "--connect-timeout 1.5" -s --connect-timeout 1.5 http://localhost/x
# --- what the helper passes to curl
rm -f "$STUB_OUT"; env -u ACTIONS_ID_TOKEN_REQUEST_URL sh "$H" -s -u mvn:acceptance-secret localhost:18098/metrics > /dev/null 2>&1
a=$(cat "$STUB_OUT" 2>/dev/null | tr '\n' ' ')
case "$a" in *"-q "*) ok "the fetch program is started with -q (no config file)";; *) bad "started with -q: $a";; esac
case "$a" in *"--noproxy * "*) ok "no proxy is used";; *) bad "no proxy: $a";; esac
case "$a" in *"--proto =http "*) ok "only the http protocol is allowed";; *) bad "--proto =http: $a";; esac
case "$a" in *"-g "*) ok "globbing is off (one operand is one request)";; *) bad "-g: $a";; esac
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
tok t "$TU" -sSf "${TU}&audience=x&extra=1"
if [ "$RC" != 0 ] && [ ! -f "$STUB_OUT" ]; then ok "refused: an audience followed by another query parameter"; else bad "audience with extra parameter (rc=$RC)"; fi
tok t "$TU" -sSf "${TU}&audience=x y"
if [ "$RC" != 0 ] && [ ! -f "$STUB_OUT" ]; then ok "refused: an audience with a space"; else bad "audience with a space (rc=$RC)"; fi
tok t "$TU" -sSf "${TU}&audience=x#frag"
if [ "$RC" != 0 ] && [ ! -f "$STUB_OUT" ]; then ok "refused: an audience with a fragment"; else bad "audience with a fragment (rc=$RC)"; fi
tok t "$TU" -sSf "${TU}&audience="
if [ "$RC" != 0 ] && [ ! -f "$STUB_OUT" ]; then ok "refused: an empty audience"; else bad "empty audience (rc=$RC)"; fi
# --- a refused or failed token request never prints the bearer value or the request token (advisor, Oct 17): not on stdout, not on stderr, whatever the failure
FAKE=fakebearer-Zx81Qq-do-not-print
TOKURL="https://pipelines.actions.example.invalid/_apis/token?x=1"
cat > "$work/bin/$STUBNAME" <<'STUB'
#!/bin/sh
case "$STUB_MODE" in
  http) echo "fetch: (22) The requested URL returned error: 403" >&2; exit 22 ;;
  net)  echo "fetch: (6) Could not resolve host" >&2; exit 6 ;;
  *)    echo "stub-ran" ;;
esac
STUB
leakcheck() {   # leakcheck NAME MODE URL...: the helper refuses or the fetch fails, and neither stream names the bearer value
  local name="$1" mode="$2"; shift 2
  out=$(STUB_MODE="$mode" ACTIONS_ID_TOKEN_REQUEST_URL="$TOKURL" ACTIONS_ID_TOKEN_REQUEST_TOKEN="$FAKE" sh "$H" -sSf -H "Authorization: bearer $FAKE" "$@" 2>&1); rc=$?
  case "$out" in *"$FAKE"*) bad "no leak: $name (the bearer value is in the output)";; *) if [ "$rc" != 0 ]; then ok "no leak: $name"; else bad "no leak: $name (expected a failure, rc=0)"; fi;; esac
}
leakcheck "a refused URL (another host)" ok "https://example.com/_apis/token?x=1&audience=sigstore"
leakcheck "a refused URL (suffix after the token URL)" ok "${TOKURL}x&audience=sigstore"
leakcheck "a refused audience" ok "${TOKURL}&audience=a b"
leakcheck "an HTTP error from the fetch program" http "${TOKURL}&audience=sigstore"
leakcheck "a network error from the fetch program" net "${TOKURL}&audience=sigstore"
leakcheck "no URL at all" ok
leakcheck "an option that is not allowed" ok --config /tmp/x "${TOKURL}&audience=sigstore"
# the helper never traces itself and never echoes its arguments
if grep -nE '(^|[[:space:];])set +-[A-Za-z]*x|set +-o +xtrace|echo +"?\$[@*]|printf .*"\$[@*]"' "$H" > /dev/null; then bad "the helper traces or echoes its arguments"; else ok "the helper never traces itself or echoes its arguments"; fi
# --- the documented smoke commands run through the helper
grep -q "^lines.append(.$STUBNAME() { sh bin/loopback-get.sh" "$root/bin/acceptance-k8s-smoke.py" && ok "the k8s smoke script routes the documented commands through the helper" || bad "the k8s smoke script does not route the documented commands through the helper"
# pin-age reads a line that starts with an assignment to a variable named url as the place a script downloads from, which no ruling can cover: the helper has none
if grep -Eq '^[ 	]*(export +|readonly +|local +)?(url|URL)=' "$H"; then bad "the helper has a line that starts with an assignment to url"; else ok "the helper has no line that starts with an assignment to url (pin-age reads it as a download source)"; fi
# --- the call sites no longer name curl
# the four scripts that change directory keep their own request lines (the named exception of REQ-SUP-001-AC24, until check-action-pins can place a relative path in a script that cds); every other call site goes through the helper
for f in acceptance-gradle.sh acceptance-gradle-capped.sh acceptance-maven.sh acceptance-maven-capped.sh; do
  if grep -q 'loopback-get.sh' "$root/bin/$f"; then bad "bin/$f names the helper (it is a named exception of AC24: it keeps its own fetch lines until check-action-pins can place a relative path in a script that cds)"; else ok "bin/$f keeps its own fetch lines (named exception of AC24)"; fi
done
for f in acceptance-serve.sh acceptance-k8s.sh acceptance-egress.sh check-artifacts.sh check-fips.sh; do
  n=$(grep -v '^[[:space:]]*#' "$root/bin/$f" | grep -c "\b$STUBNAME\b" || true)
  case "$f" in
    # the egress script keeps the strace download (the pinned fetch of the production PR); the k8s script keeps the digest-pinned client image name
    acceptance-egress.sh) lim=2;;
    acceptance-k8s.sh) lim=1;;
    *) lim=0;;
  esac
  if [ "$n" -le "$lim" ]; then ok "bin/$f has no fetch program of its own outside the loopback helper ($n)"; else bad "bin/$f still names the fetch program $n time(s)"; fi
  grep -q 'loopback-get.sh' "$root/bin/$f" && ok "bin/$f calls the helper" || bad "bin/$f does not call the helper"
done
# the helper function is defined where every step function sees it: at the top level, before the first function whose body is a subshell
for f in acceptance-serve.sh acceptance-egress.sh check-artifacts.sh check-fips.sh; do
  d=$(grep -n '^lg\(in\)\?() ' "$root/bin/$f" | head -1 | cut -d: -f1)
  fn=$(grep -n '^[a-z_0-9]*() *(' "$root/bin/$f" | head -1 | cut -d: -f1)
  if [ -n "$d" ] && { [ -z "$fn" ] || [ "$d" -lt "$fn" ]; }; then ok "bin/$f defines its loopback function at the top level"; else bad "bin/$f defines its loopback function inside a step (line ${d:-none}, first step line ${fn:-none})"; fi
done
# the three requests to the runner's token endpoint go through the helper, with the bearer in the header option and nothing else changed
for f in witnessed.sh chain-hostile-step.sh; do
  n=$(grep -v '^[[:space:]]*#' "$root/bin/$f" | grep -c "\b$STUBNAME\b" || true)
  lim=0
  # the hostile step keeps one fixture string that spells a malicious step name
  [ "$f" = chain-hostile-step.sh ] && lim=1
  if [ "$n" -le "$lim" ]; then ok "bin/$f has no fetch program of its own ($n)"; else bad "bin/$f still names the fetch program $n time(s)"; fi
  grep -q 'sh bin/loopback-get.sh ' "$root/bin/$f" && ok "bin/$f calls the helper" || bad "bin/$f does not call the helper"
done
echo "loopback-get: $pass passed, $failn failed"
[ "$failn" = 0 ]
