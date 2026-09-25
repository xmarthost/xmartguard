#!/usr/bin/env bash
# shellcheck disable=SC2034  # variables are used inside eval-ed check strings
# Exercises installer/install.sh and installer/uninstall.sh end-to-end against
# a running portal on a disposable machine. With real systemd (CI runners,
# VMs) the real service manager is used; without it (dev containers) a stub
# `systemctl` runs the agent as a background process.
#
#   PORTAL=http://localhost:8080 ADMIN_EMAIL=... ADMIN_PASSWORD=... scripts/test-installer.sh
#
# DESTRUCTIVE: installs into /usr/local/bin, /etc/xmartguard, /var/lib/xmartguard.
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
# Minimal systemctl stand-in for xmartguard-agent.service only.
PIDF=/run/xg-stub.pid
UNIT=/etc/systemd/system/xmartguard-agent.service
running() { [ -f $PIDF ] && kill -0 "$(cat $PIDF)" 2>/dev/null; }
start() {
  running && return 0
  exec_start=$(sed -n 's/^ExecStart=//p' $UNIT)
  mkdir -p /var/log/xmartguard
  nohup $exec_start >>/var/log/xmartguard/agent.log 2>&1 &
  echo $! >$PIDF
}
stop() { running && kill "$(cat $PIDF)" && sleep 1; rm -f $PIDF; }
args=("$@"); now=0
for a in "${args[@]}"; do [ "$a" = "--now" ] && now=1; done
case "$1" in
  daemon-reload|reset-failed) exit 0 ;;
  enable)  [ $now = 1 ] && start; exit 0 ;;
  disable) [ $now = 1 ] && stop; exit 0 ;;
  start)   start ;;
  stop)    stop ;;
  is-active) running ;;
  list-unit-files|cat) [ -f $UNIT ] ;;
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
  curl -fsS -b "$CJ" "$PORTAL/api/servers" | grep -o '"id":"' | wc -l
}

echo "== install =="
before=$(server_count)
TOKEN=$(new_token)
curl -fsSL "$PORTAL/install.sh" | bash -s -- --token "$TOKEN" | tee "$WORK/install.out"
check "binary installed"          '[ -x /usr/local/bin/xmartguard-agent ]'
check "config is 0600"            '[ "$(stat -c %a /etc/xmartguard/agent.json)" = 600 ]'
check "identity key is 0600"      '[ "$(stat -c %a /etc/xmartguard/identity.key)" = 600 ]'
check "config dir is 0700"        '[ "$(stat -c %a /etc/xmartguard)" = 700 ]'
check "manifest written"          'grep -q "^file /usr/local/bin/xmartguard-agent$" /var/lib/xmartguard/manifest'
check "unit written"              'grep -q "ExecStart=/usr/local/bin/xmartguard-agent run" /etc/systemd/system/xmartguard-agent.service'
check "agent running"             'systemctl is-active xmartguard-agent'
check "local uninstaller saved"   '[ -x /var/lib/xmartguard/uninstall.sh ]'
sleep 3
check "server appears in portal"  '[ "$(server_count)" -eq $((before+1)) ]'
check "agent log shows connection" 'grep -q "connected to portal" /var/log/xmartguard/agent.log'

echo "== second install is refused without --force =="
check "reinstall refused" '! curl -fsSL "$PORTAL/install.sh" | bash -s -- --token "$(new_token)" >/dev/null 2>&1'

echo "== used token is rejected =="
check "used token rejected" '! /usr/local/bin/xmartguard-agent enroll --force --server "$PORTAL" --token "$TOKEN" >/dev/null 2>&1'

echo "== uninstall dry run changes nothing =="
bash /var/lib/xmartguard/uninstall.sh --dry-run >/dev/null
check "dry run kept files" '[ -x /usr/local/bin/xmartguard-agent ] && systemctl is-active xmartguard-agent'

echo "== uninstall =="
curl -fsSL "$PORTAL/uninstall.sh" | bash | tee "$WORK/uninstall.out"
check "uninstaller reports clean"  'grep -q "removed completely" "$WORK/uninstall.out"'
check "binary removed"             '[ ! -e /usr/local/bin/xmartguard-agent ] && [ ! -L /usr/local/bin/xmartguard ]'
check "config removed"             '[ ! -e /etc/xmartguard ]'
check "state removed"              '[ ! -e /var/lib/xmartguard ]'
check "logs removed"               '[ ! -e /var/log/xmartguard ]'
check "unit removed"               '[ ! -e /etc/systemd/system/xmartguard-agent.service ]'
check "agent stopped"              '! pgrep -f "/usr/local/bin/xmartguard-agent run" >/dev/null'
check "server removed from portal" '[ "$(server_count)" -eq "$before" ]'

echo "== bad token fails cleanly and leaves no service =="
out=$(curl -fsSL "$PORTAL/install.sh" | bash -s -- --token XG-AAAA-BBBB-CCCC-DDDD-EEEE 2>&1 || true)
check "bad token message"   'grep -q "enrollment failed" <<<"$out"'
check "no service after failure" '! systemctl is-active xmartguard-agent'
bash <(curl -fsSL "$PORTAL/uninstall.sh") --no-unenroll >/dev/null 2>&1 || true
check "cleanup after failed install" '[ ! -e /etc/xmartguard ] && [ ! -e /var/lib/xmartguard ] && [ ! -e /usr/local/bin/xmartguard-agent ]'

echo ""
echo "installer tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
