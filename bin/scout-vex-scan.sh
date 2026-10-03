#!/usr/bin/env bash
# Scanner-panel rule 4: Docker Scout reads our OpenVEX file directly. Scout applies only statements whose author matches
# --vex-author (default Docker's own), so ours is named — the anchored, escaped author of the published file. The
# rescan's scan and its self-check both run THIS command, so their flags cannot drift apart.
# Usage: scout-vex-scan.sh <local image ref> <vex file> <out: Scout's GitLab report>
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
author=$(jq -er .author "$here/../.vex/fosterstack-cache.openvex.json")
re="^$(printf '%s' "$author" | sed 's/[][\.*^$+?(){}|/]/\\&/g')\$"
docker scout cves --format gitlab --vex-location "$2" --vex-author "$re" "local://$1" > "$3"
