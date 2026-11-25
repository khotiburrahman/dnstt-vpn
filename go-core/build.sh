#!/usr/bin/env bash
set -e

mkdir -p ../android/app/libs

gomobile bind \
    -target=android/arm64,android/arm \
    -androidapi 24 \
    -ldflags="-s -w" \
    -o ../android/app/libs/dnstt.aar \
    ./mobile

echo "Build AAR berhasil: ../android/app/libs/dnstt.aar"
