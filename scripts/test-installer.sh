#!/usr/bin/env bash
# shellcheck disable=SC2034  # variables are used inside eval-ed check strings
# Exercises installer/install.sh and installer/uninstall.sh end-to-end against
# a running portal on a disposable machine. With real systemd (CI runners,
# VMs) the real service manager is used; without it (dev containers) a stub
# `systemctl` runs the agent as a background process.
#
#   PORTAL=http://localhost:8080 ADMIN_EMAIL=... ADMIN_PASSWORD=... scripts/test-installer.sh
#
# DESTRUCTIVE: installs into /opt/xpguard, /opt/xmartguard, /etc/xmartguard and /usr/local/bin.
set -euo pipefail

PORTAL="${PORTAL:-http://localhost:8080}"
ADMIN_EMAIL="${ADMIN_EMAIL:?set ADMIN_EMAIL}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:?set ADMIN_PASSWORD}"
WORK=$(mktemp -d)
STUB=$WORK/bin
mkdir -p "$STUB"
if [ -d /run/systemd/system ]; then
  echo "using real systemd"
  trap 'rm -rf "$WORK"' EXIT
else
  echo "no systemd: using a stub systemctl"
  mkdir -p /run/systemd/system
  trap 'rm -rf "$WORK" /run/systemd' EXIT

cat >"$STUB/systemctl" <<'EOF'
#!/usr/bin/env bash
# Minimal systemctl stand-in: one background process per unit name.
name=""
for a in "$@"; do
  case "$a" in
    -*|enable|disable|start|stop|is-active|list-unit-files|cat|daemon-reload|reset-failed) ;;
    *) name=${a%.service}; break ;;
  esac
done
UNIT=/etc/systemd/system/$name.service
PIDF=/run/xg-stub-$name.pid
running() { [ -n "$name" ] && [ -f "$PIDF" ] && kill -0 "$(cat "$PIDF")" 2>/dev/null; }
start() {
  running && return 0
  [ -f "$UNIT" ] || return 1
  exec_start=$(sed -n 's/^ExecStart=//p' "$UNIT")
  log=$(sed -n 's/^StandardOutput=append://p' "$UNIT")
  mkdir -p "$(dirname "$log")"
  nohup $exec_start >>"$log" 2>&1 &
  echo $! >"$PIDF"
}
stop() { running && kill "$(cat "$PIDF")" && sleep 1; rm -f "$PIDF"; }
now=0
for a in "$@"; do [ "$a" = "--now" ] && now=1; done
case "$1" in
  daemon-reload|reset-failed) exit 0 ;;
  enable)  [ $now = 1 ] && start; exit 0 ;;
  disable) [ $now = 1 ] && stop; exit 0 ;;
  start)   start ;;
  stop)    stop ;;
  is-active) running ;;
  list-unit-files|cat) [ -f "$UNIT" ] ;;
  *) exit 0 ;;
esac
EOF
chmod +x "$STUB/systemctl"
fi
export PATH="$STUB:$PATH"

pass=0; fail=0
check() { if eval "$2"; then echo "  PASS  $1"; pass=$((pass+1)); else echo "  FAIL  $1"; fail=$((fail+1)); fi; }

CJ=$WORK/cookies
curl -fsS -c "$CJ" -H 'content-type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" "$PORTAL/api/auth/login" >/dev/null
new_token() {
  curl -fsS -b "$CJ" -H 'content-type: application/json' -d '{"label":"installer-test"}' \
    "$PORTAL/api/enrollment-tokens" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p'
}
server_count() {
  curl -fsS -b "$CJ" "$PORTAL/api/servers" | { grep -o '"id":"' || true; } | wc -l
}

echo "== install =="
before=$(server_count)
TOKEN=$(new_token)
curl -fsSL "$PORTAL/install.sh" | bash -s -- --token "$TOKEN" | tee "$WORK/install.out"
check "binary installed in /opt"  '[ -x /opt/xpguard/bin/xpguard-agent ] && [ ! -L /opt/xpguard/bin/xpguard-agent ]'
check "binary linked into PATH"   '[ "$(readlink /usr/local/bin/xpguard-agent)" = /opt/xpguard/bin/xpguard-agent ]'
check "old program path kept"     '[ "$(readlink /opt/xmartguard/bin/xmartguard-agent)" = /opt/xpguard/bin/xpguard-agent ]'
check "config is 0600"            '[ "$(stat -c %a /etc/xmartguard/agent.json)" = 600 ]'
check "identity key is 0600"      '[ "$(stat -c %a /etc/xmartguard/identity.key)" = 600 ]'
check "config dir is 0700"        '[ "$(stat -c %a /etc/xmartguard)" = 700 ]'
check "manifest written"          'grep -q "^file /opt/xpguard/bin/xpguard-agent$" /opt/xmartguard/manifest'
check "unit written"              'grep -q "ExecStart=/opt/xpguard/bin/xpguard-agent run" /etc/systemd/system/xpguard-agent.service'
check "agent running"             'systemctl is-active --quiet xpguard-agent'
check "process shows xpguard"     'pgrep -f "/opt/xpguard/bin/xpguard-agent run" >/dev/null && ! pgrep -f "xmartguard-agent run" >/dev/null'
check "local uninstaller saved"   '[ -x /opt/xmartguard/uninstall.sh ]'
sleep 3
check "server appears in portal"  '[ "$(server_count)" -eq $((before+1)) ]'
check "agent log shows connection" 'grep -q "connected to portal" /opt/xmartguard/logs/agent.log'
check "data dir created"          '[ -f /opt/xmartguard/data/agent.db ] && [ "$(stat -c %a /opt/xmartguard/data)" = 700 ]'
check "local control socket"      'xpguard-agent call overview | grep -q "\"version\""'

echo "== second install is refused without --force =="
check "reinstall refused" '! curl -fsSL "$PORTAL/install.sh" | bash -s -- --token "$(new_token)" >/dev/null 2>&1'

echo "== used token is rejected =="
check "used token rejected" '! /usr/local/bin/xpguard-agent enroll --force --server "$PORTAL" --token "$TOKEN" >/dev/null 2>&1'

echo "== uninstall dry run changes nothing =="
bash /opt/xmartguard/uninstall.sh --dry-run >/dev/null
check "dry run kept files" '[ -x /usr/local/bin/xpguard-agent ] && systemctl is-active --quiet xpguard-agent'

echo "== uninstall =="
curl -fsSL "$PORTAL/uninstall.sh" | bash | tee "$WORK/uninstall.out"
check "uninstaller reports clean"  'grep -q "removed completely" "$WORK/uninstall.out"'
check "binary removed"             '[ ! -L /usr/local/bin/xpguard-agent ] && [ ! -e /opt/xpguard ] && [ ! -L /usr/local/bin/xmartguard-agent ]'
check "config removed"             '[ ! -e /etc/xmartguard ]'
check "state and logs removed"     '[ ! -e /opt/xmartguard ] && [ ! -e /var/lib/xmartguard ]'
check "socket removed"             '[ ! -e /run/xmartguard ]'
check "unit removed"               '[ ! -e /etc/systemd/system/xpguard-agent.service ] && [ ! -e /etc/systemd/system/xmartguard-agent.service ]'
check "agent stopped"              '! pgrep -f "xpguard-agent run" >/dev/null'
check "server removed from portal" '[ "$(server_count)" -eq "$before" ]'

echo "== bad token fails cleanly and leaves no service =="
out=$(curl -fsSL "$PORTAL/install.sh" | bash -s -- --token XG-AAAA-BBBB-CCCC-DDDD-EEEE 2>&1 || true)
check "bad token message"   'grep -q "enrollment failed" <<<"$out"'
check "no service after failure" '! systemctl is-active --quiet xpguard-agent'
bash <(curl -fsSL "$PORTAL/uninstall.sh") --no-unenroll >/dev/null 2>&1 || true
check "cleanup after failed install" '[ ! -e /etc/xmartguard ] && [ ! -e /opt/xmartguard ] && [ ! -e /opt/xpguard ] && [ ! -L /usr/local/bin/xpguard-agent ]'

echo ""
echo "installer tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
