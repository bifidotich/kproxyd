#!/bin/sh
# Сборка kproxyd для Keenetic. Нужен Go 1.22+, внешних зависимостей нет.
# Версию можно задать: VERSION=v0.2.0 ./build.sh (по умолчанию — из git).
set -e
cd "$(dirname "$0")"
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
mkdir -p dist
build() { echo "-> $T"; CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "dist/kproxyd-$T" . ; }
T=mipsel GOARCH=mipsle GOMIPS=softfloat build
T=mips GOARCH=mips GOMIPS=softfloat build
T=aarch64 GOARCH=arm64 build
echo "версия: $VERSION"
ls -la dist
