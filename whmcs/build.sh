#!/usr/bin/env bash
# Packages the addon as xmarthost_mcp-<version>.zip, ready to upload to the WHMCS root
# (unzip there: it creates modules/addons/xmarthost_mcp/).
set -euo pipefail
cd "$(dirname "$0")"
VERSION=$(sed -n "s/.*define('XMH_MCP_VERSION', '\([^']*\)').*/\1/p" modules/addons/xmarthost_mcp/lib/autoload.php)
OUT="${1:-$PWD/dist}"
mkdir -p "$OUT"
rm -f "$OUT/xmarthost_mcp-$VERSION.zip"
zip -qr "$OUT/xmarthost_mcp-$VERSION.zip" modules/addons/xmarthost_mcp -x '*.DS_Store'
echo "$OUT/xmarthost_mcp-$VERSION.zip"
