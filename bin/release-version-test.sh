#!/usr/bin/env bash
# bin/release-version.sh prints the version a ref releases: the tag itself on a tag push, the next patch of the
# line on a release/vX.Y branch, and fails with no output on any other ref. Runs in a throwaway repo.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir "$work/bin"; cp "$here/release-version.sh" "$work/bin/"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null
git -C "$work" init -q
git -C "$work" commit -q --allow-empty -m init
pass=0; fail=0
ok() { echo "ok: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; fail=$((fail+1)); }
run() { # ref, ref_name -> stdout in $out, status in $rc
  out=$(cd "$work" && GITHUB_REF=$1 GITHUB_REF_NAME=$2 bin/release-version.sh 2>/dev/null); rc=$?
}
expect() { # name, want, ref, ref_name
  run "$3" "$4"
  if [ "$rc" -eq 0 ] && [ "$out" = "$2" ]; then ok "$1"; else bad "$1 (rc=$rc, got '$out', want '$2')"; fi
}
expect "a tag push prints the tag" v0.3.0 refs/tags/v0.3.0 v0.3.0
expect "a release branch with no tag of its line prints v0.3.0" v0.3.0 refs/heads/release/v0.3 release/v0.3
for t in v0.2.5 v0.4.0; do git -C "$work" tag "$t"; done
expect "tags of other lines do not count" v0.3.0 refs/heads/release/v0.3 release/v0.3
git -C "$work" tag v0.3.0
expect "v0.3.0 present gives v0.3.1" v0.3.1 refs/heads/release/v0.3 release/v0.3
git -C "$work" tag v0.3.1
expect "v0.3.0 and v0.3.1 present give v0.3.2" v0.3.2 refs/heads/release/v0.3 release/v0.3
for t in v0.3.9 v0.3.10; do git -C "$work" tag "$t"; done
expect "v0.3.9 and v0.3.10 present give v0.3.11" v0.3.11 refs/heads/release/v0.3 release/v0.3
for t in v0.5.0-rc1 v0.5.0-rc2; do git -C "$work" tag "$t"; done
expect "only release candidates of the line give v0.5.0" v0.5.0 refs/heads/release/v0.5 release/v0.5
for t in v0.6.0-rc1 v0.6.0-rc2 v0.6.0; do git -C "$work" tag "$t"; done
expect "release candidates and v0.6.0 present give v0.6.1" v0.6.1 refs/heads/release/v0.6 release/v0.6
for t in v0.7.0 v0.7.1-rc.1; do git -C "$work" tag "$t"; done
expect "v0.7.0 and v0.7.1-rc.1 present give v0.7.1" v0.7.1 refs/heads/release/v0.7 release/v0.7
run refs/heads/main main
if [ "$rc" -ne 0 ] && [ -z "$out" ]; then ok "another ref exits non-zero with no output"; else bad "another ref (rc=$rc, out '$out')"; fi
echo "release-version: $pass passed, $fail failed"; [ "$fail" -eq 0 ]
