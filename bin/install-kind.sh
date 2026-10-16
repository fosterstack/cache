#!/usr/bin/env bash
# bin/install-kind.sh: kind v0.33.0 and kubectl v1.37.0 for the Check runner (REQ-CHAIN-006-AC14; advisor ruling Q8, Oct 10).
# Exact versions, linux amd64 only (Check runs on ubuntu-24.04), each verified against its committed sha256 before it is installed; no
# action installs them. Source of the versions and of the node image digest the k8s suite uses: the kind v0.33.0 release notes,
# https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0 (published 2026-08-26). The exact lines are judged by
# the kind judge of the Check wiring test; change both together.
set -euo pipefail
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || { echo "install-kind: only linux amd64 is pinned (the Check runner is ubuntu-24.04)" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/kind" https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-linux-amd64
curl -fsSL -o "$tmp/kubectl" https://dl.k8s.io/release/v1.37.0/bin/linux/amd64/kubectl
printf '%s  %s\n' aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d "$tmp/kind" 6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f "$tmp/kubectl" | sha256sum -c -
install -m 0755 "$tmp/kind" "$tmp/kubectl" /usr/local/bin/
kind version
kubectl version --client
