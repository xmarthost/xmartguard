#!/usr/bin/env bash
# shellcheck disable=SC2034  # variables are used inside eval-ed check strings
# Checks of installer/ and deploy/ scripts that need no root, no network and
# no portal: each one runs a piece of a script against stub commands in a
# temporary folder and changes nothing on this machine.
#
#   scripts/test-deploy.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

pass=0; fail=0
check() { if eval "$2"; then echo "  PASS  $1"; pass=$((pass+1)); else echo "  FAIL  $1"; fail=$((fail+1)); fi; }

echo "== selftest.sh shows the firewall chain the agent uses =="
cat >"$WORK/bin/iptables" <<'EOF'
#!/bin/sh
# Stub: XG_CHAIN is the chain the (fake) agent created.
case "$*" in
  "-w -S $XG_CHAIN") echo "-N $XG_CHAIN" ;;
  "-w -S INPUT") echo "-P INPUT ACCEPT"; echo "-A INPUT -j $XG_CHAIN" ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$WORK/bin/iptables"
sed -n '/^# Agents since the xPGuard name/,/^echo "--- INPUT jump"/p' "$ROOT/installer/selftest.sh" >"$WORK/fw.sh"
out=$(XG_CHAIN=XPGUARD PATH="$WORK/bin:$PATH" bash "$WORK/fw.sh" 2>&1)
check "current agent: XPGUARD chain"  'grep -q -- "--- XPGUARD chain" <<<"$out" && grep -q -- "-A INPUT -j XPGUARD" <<<"$out" && ! grep -q "no jump" <<<"$out"'
out=$(XG_CHAIN=XMARTGUARD PATH="$WORK/bin:$PATH" bash "$WORK/fw.sh" 2>&1)
check "old agent: XMARTGUARD chain"   'grep -q -- "--- XMARTGUARD chain" <<<"$out" && grep -q -- "-A INPUT -j XMARTGUARD" <<<"$out"'

echo ""
echo "deploy script tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
