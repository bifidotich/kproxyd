#!/bin/sh
# Сборка kproxyd для Keenetic. Нужен Go 1.22+, внешних зависимостей нет.
set -e
cd "$(dirname "$0")"
mkdir -p dist
build() { echo "-> $T"; CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o "dist/kproxyd-$T" . ; }
T=mipsel GOARCH=mipsle GOMIPS=softfloat build
T=mips GOARCH=mips GOMIPS=softfloat build
T=aarch64 GOARCH=arm64 build
ls -la dist
