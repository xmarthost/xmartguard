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

echo "== install.sh: https only, http and --insecure only for localhost =="
# Never given a token: a run that passes the address checks stops at the
# token check (or, without root, at the root check) before changing anything.
inst() { bash "$ROOT/installer/install.sh" "$@" 2>&1 || true; }
URLERR="must start with https|only allowed for a portal on this machine|invalid --server"
for u in http://203.0.113.10 http://portal.example.com:8080/ "http://127.0.0.1.example.com" "http://evil.example#@127.0.0.1" "http://127.0.0.1@evil.example" ftp://portal.example.com; do
  out=$(inst --server "$u")
  check "refused: $u" 'grep -Eq "$URLERR" <<<"$out"'
done
out=$(inst --server https://portal.example.com --insecure)
check "refused: --insecure for a remote portal" 'grep -q "only allowed for a portal on this machine" <<<"$out"'
for a in "--server https://portal.example.com" "--server http://localhost:8080" "--server http://127.0.0.1:8080/" "--server http://[::1]:8080" "--server https://127.0.0.1 --insecure"; do
  # shellcheck disable=SC2086  # split into options on purpose
  out=$(inst $a)
  check "accepted: $a" '! grep -Eq "$URLERR" <<<"$out" && grep -Eq "missing --token|please run as root" <<<"$out"'
done

echo ""
echo "deploy script tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
