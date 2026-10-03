#!/usr/bin/env bash
# End-to-end: serves the real mcp.php through PHP's built-in web server, with
# the module connected in "API credentials" mode to a fake WHMCS includes/api.php.
set -euo pipefail
cd "$(dirname "$0")"

ROOT=.e2e_root
PORT=${PORT:-8765}
export XMH_TEST_DB="$PWD/.e2e.sqlite"
rm -rf "$ROOT" "$XMH_TEST_DB"
mkdir -p "$ROOT/modules/addons"
cp -r fake_whmcs/. "$ROOT/"
cp -r ../modules/addons/xmarthost_mcp "$ROOT/modules/addons/"

# Seed WHMCS, activate the module, configure API mode and create a connector.
TOKEN=$(php -r '
  require "bootstrap.php";
  require "../modules/addons/xmarthost_mcp/xmarthost_mcp.php";
  xmh_seed_whmcs();
  xmarthost_mcp_activate();
  \XMartHost\Mcp\Settings::setMany(["connection_mode" => "api", "api_url" => "http://127.0.0.1:'"$PORT"'/", "api_identifier" => "ID123", "api_secret" => "SECRET456", "require_https" => "0"]);
  echo \XMartHost\Mcp\Tokens::create("e2e", "write", [], [], 0, "ci")["token"];
')

PHP_CLI_SERVER_WORKERS=4 php -S 127.0.0.1:$PORT -t "$ROOT" > .e2e_server.log 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null; rm -rf "$ROOT" "$XMH_TEST_DB"' EXIT
for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done

URL="http://127.0.0.1:$PORT/modules/addons/xmarthost_mcp/mcp.php"
fail=0
check() { # name, expected substring, actual
  if [[ "$3" == *"$2"* ]]; then echo "  ok   $1"; else echo "  FAIL $1"; echo "       got: ${3:0:400}"; fail=1; fi
}
post() { curl -s -w '\n%{http_code}' -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' "$@"; }

r=$(post "$URL?key=$TOKEN" -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}')
check "initialize over HTTP" '"name":"xmarthost-whmcs"' "$r"
check "initialize status 200" $'\n200' "$r"

r=$(post "$URL?key=$TOKEN" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}')
check "notification -> 202" "202" "$r"

r=$(post "$URL" -H "Authorization: Bearer $TOKEN" -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}')
check "tools/list with Bearer header" '"create_product"' "$r"

r=$(post "$URL/$TOKEN" -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"whmcs_overview","arguments":{}}}')
check "overview through WHMCS API credentials" '8.13.0' "$r"
check "overview isError false" '"isError":false' "$r"

r=$(post "$URL?key=$TOKEN" -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search_clients","arguments":{"search":"ali"}}}')
check "search_clients through API" 'ali@example.com' "$r"

r=$(post "$URL?key=bad" -d '{"jsonrpc":"2.0","id":5,"method":"ping"}')
check "bad key -> 401" $'\n401' "$r"

r=$(curl -s -w '\n%{http_code}' "$URL?key=$TOKEN")
check "GET -> 405" $'\n405' "$r"

# Wrong API secret: the tool call must fail cleanly with WHMCS's message.
php -r 'require "bootstrap.php"; require "../modules/addons/xmarthost_mcp/lib/autoload.php"; \XMartHost\Mcp\Settings::set("api_secret", "WRONG");'
r=$(post "$URL?key=$TOKEN" -d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"search_clients","arguments":{}}}')
check "wrong API secret reported" 'Authentication Failed' "$r"
check "wrong API secret isError" '"isError":true' "$r"

# Module deactivated -> endpoint refuses.
php -r 'require "bootstrap.php"; \WHMCS\Database\Capsule::table("tbladdonmodules")->delete();'
r=$(post "$URL?key=$TOKEN" -d '{"jsonrpc":"2.0","id":7,"method":"ping"}')
check "inactive module -> 503" $'\n503' "$r"

if grep -qiE "fatal|warning|notice|deprecated" .e2e_server.log; then echo "  FAIL server log has PHP errors"; grep -iE "fatal|warning|notice|deprecated" .e2e_server.log | head; fail=1; else echo "  ok   no PHP warnings in server log"; fi
rm -f .e2e_server.log
[ $fail = 0 ] && echo "e2e passed" || { echo "e2e FAILED"; exit 1; }
