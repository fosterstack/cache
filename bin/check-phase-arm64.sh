#!/usr/bin/env bash
bash bin/check-artifacts.sh --arch arm64 --digests witness-build/digests.json --images images --archives dist --out check-results
