#!/usr/bin/env bash
# Puts the agent binaries for the portal into $OUT (served at /downloads/):
# the signed ones from the GitHub release v<VERSION> made by the release
# workflow (.github/workflows/release.yml), with their .sha256 and .sig.
# Agents with a release key (agent/internal/updater/signature.go) take only
# these. While the agent has no release key yet, the binaries are built
# here instead when the release is not there (the way before signing).
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(cat VERSION 2>/dev/null || echo 0.0.0-dev)}"
OUT="${OUT:-dist/downloads}"
RELEASES="${XPGUARD_RELEASES:-https://github.com/xmarthost/xmartguard/releases/download}"
# How long to wait for the release workflow after a push (it takes a few
# minutes); only when the agent needs signed binaries.
WAIT="${XPGUARD_RELEASE_WAIT:-900}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

signed=0
if grep -q 'BEGIN PUBLIC KEY' agent/internal/updater/signature.go; then signed=1; fi

fetch() {
  local tmp f e
  tmp="$(mktemp -d)"
  for f in xpguard-agent-linux-amd64 xpguard-agent-linux-arm64; do
    for e in "" .sha256 .sig; do
      curl -fsSL --retry 2 -o "$tmp/$f$e" "$RELEASES/v$VERSION/$f$e" || { rm -rf "$tmp"; return 1; }
    done
    (cd "$tmp" && sha256sum -c --quiet "$f.sha256") || { echo "checksum of $f does not match its release" >&2; rm -rf "$tmp"; return 2; }
  done
  mv -f "$tmp"/xpguard-agent-linux-* "$OUT/"
  rm -rf "$tmp"
  echo "$VERSION" > "$OUT/VERSION"
  echo "signed agent $VERSION taken from the release"
}

waited=0
while :; do
  rc=0
  fetch || rc=$?
  [ "$rc" = 0 ] && exit 0
  [ "$rc" = 2 ] && exit 1
  if [ "$signed" = 0 ]; then
    echo "no signed release v$VERSION: building the agent here (it has no release key yet)"
    exec bash scripts/build-agent.sh
  fi
  if [ "$waited" -ge "$WAIT" ]; then
    echo "the signed release v$VERSION is not on GitHub (check the Release workflow and the XPGUARD_SIGNING_KEY secret)" >&2
    exit 1
  fi
  echo "waiting for the signed release v$VERSION ($waited s)..."
  sleep 30
  waited=$((waited + 30))
done
