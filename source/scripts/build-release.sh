#!/usr/bin/env bash
# XER v0.0 reproducible, unprivileged cross-platform build (unsigned).
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-dist}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
go test ./...
go vet ./...
for target in linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64; do
  os="${target%/*}"; arch="${target#*/}"
  ext=''; [[ "$os" == windows ]] && ext='.exe'
  echo "Building $target"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "$OUT/xer-$os-$arch$ext" .
done
CGO_ENABLED=0 go run ./cmd/xer-artifact manifest --dir "$OUT" --manifest "$OUT/SHA256SUMS"
echo "Release built in $OUT (unsigned, SHA256SUMS generated)."
