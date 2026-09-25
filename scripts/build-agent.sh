#!/usr/bin/env bash
# Builds static agent binaries for linux/amd64 and linux/arm64 into
# dist/downloads (served by the portal at /downloads/).
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)}"
OUT="${OUT:-dist/downloads}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
for arch in amd64 arm64; do
  f="$OUT/xmartguard-agent-linux-$arch"
  (cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
    -ldflags "-s -w -X github.com/xmarthost/xmartguard/agent/internal/version.Version=$VERSION" \
    -o "$f" ./cmd/xmartguard-agent)
  (cd "$OUT" && sha256sum "$(basename "$f")" > "$(basename "$f").sha256")
  echo "built $f ($VERSION)"
done
