#!/bin/sh
# proves: REQ-SUP-001-AC24 (advisor reading, Oct 17)
# The only way a program of this repository reaches a local or in-cluster address, so the pin-age check can see that no line fetches software:
#   loopback-get.sh [OPTION...] URL      (curl options from a closed list; exactly one URL)
# The URL must be http://localhost, http://127.0.0.1 or http://fscache (the in-cluster Service), each with an optional :port and a path that
# starts with "/" (the scheme may be left out), or the runner's own token endpoint: the value of ACTIONS_ID_TOKEN_REQUEST_URL (https), alone or
# followed by &audience=<value>. Anything else is refused before curl starts. curl is started with -q (no .curlrc), no proxy, one protocol only,
# and no redirect followed. Options: -s -S -f -I -g (alone or combined), -X GET|PUT|POST|HEAD, -u, -H, -o, -D, -w, --data-binary, --max-time N,
# --connect-timeout N. Plain POSIX shell: it also runs inside a container or a pod, fed on stdin.
set -eu
fail() { echo "loopback-get: refused: $*" >&2; exit 2; }
n=$#; i=0; url=""; urls=0
while [ "$i" -lt "$n" ]; do
  a=$1; shift; i=$((i + 1))
  case "$a" in
    -X)
      [ "$i" -lt "$n" ] || fail "-X needs a method"
      v=$1; shift; i=$((i + 1))
      case "$v" in GET|PUT|POST|HEAD) ;; *) fail "method $v";; esac
      set -- "$@" -X "$v" ;;
    -u|-H|-o|-D|-w|--data-binary)
      [ "$i" -lt "$n" ] || fail "$a needs a value"
      v=$1; shift; i=$((i + 1))
      set -- "$@" "$a" "$v" ;;
    --max-time|--connect-timeout)
      [ "$i" -lt "$n" ] || fail "$a needs a value"
      v=$1; shift; i=$((i + 1))
      [ -n "$v" ] || fail "$a needs a number"
      case "$v" in *[!0-9.]*|.*|*.|*.*.*) fail "$a needs a number";; esac
      set -- "$@" "$a" "$v" ;;
    -[sSfIg]*)
      case "${a#-}" in *[!sSfIg]*) fail "option $a";; esac
      set -- "$@" "$a" ;;
    -*) fail "option $a" ;;
    *) urls=$((urls + 1)); url=$a ;;
  esac
done
[ "$urls" = 1 ] || fail "exactly one URL is required (got $urls)"
proto=http
tok=${ACTIONS_ID_TOKEN_REQUEST_URL:-}
case "$tok" in https://*) ;; *) tok="" ;; esac
if [ -n "$tok" ] && { [ "$url" = "$tok" ] || case "$url" in "$tok&audience="*) true;; *) false;; esac; }; then
  aud=${url#"$tok"}
  case "$aud" in "") ;; "&audience="?*) case "${aud#&audience=}" in *[!A-Za-z0-9:/._-]*) fail "the audience holds a character outside the list" ;; esac ;; *) fail "the token URL has a suffix other than &audience=" ;; esac
  proto=https
else
  bad=$(printf '%s' "$url" | tr -d 'A-Za-z0-9._~:/?=&%+-' | wc -c)
  [ "$bad" -eq 0 ] || fail "a URL with a character outside the plain URL characters (whitespace, backslash, fragment, glob)"
  case "$url" in
    http://*) rest=${url#http://} ;;
    *://*) fail "scheme of $url" ;;
    *) rest=$url ;;
  esac
  hostport=${rest%%[/?#]*}
  tail=${rest#"$hostport"}
  case "$tail" in [/]*) ;; *) fail "the URL needs a path starting with /" ;; esac
  case "$hostport" in *[!A-Za-z0-9.:]*|"") fail "host $hostport" ;; esac
  host=${hostport%%:*}
  case "$host" in localhost|127.0.0.1|fscache) ;; *) fail "host $host" ;; esac
  if [ "$host" != "$hostport" ]; then
    port=${hostport#*:}
    [ -n "$port" ] || fail "port"
    case "$port" in *[!0-9]*) fail "port $port" ;; esac
  fi
  rest="http://$rest"; url=$rest
fi
curl -q -g --noproxy '*' --proto "=$proto" --max-redirs 0 "$@" "$url" || exit $?
