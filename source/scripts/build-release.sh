#!/usr/bin/env bash
# XER development release: cross-platform build, unsigned.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-dist}"
if [[ -e "$OUT" ]] && [[ -n "$(find "$OUT" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo 'Output directory must be empty; use a new directory for this release.' >&2
  exit 1
fi
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
go build ./...
go test ./...
go test -race ./...
go vet ./...
for target in linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64; do
  os="${target%/*}"; arch="${target#*/}"
  ext=''; [[ "$os" == windows ]] && ext='.exe'
  echo "Building $target"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags='-s -w' -o "$OUT/xer-$os-$arch$ext" .
done
CGO_ENABLED=0 go run ./cmd/xer-artifact manifest --dir "$OUT" --manifest "$OUT/SHA256SUMS"
echo "Release built in $OUT (unsigned, SHA256SUMS generated)."
