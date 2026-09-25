#!/usr/bin/env bash
# XMart Guard real-server self test. Run as root on the TEST server after
# installing the agent with the command from the portal:
#
#   curl -fsSL __XG_PORTAL_URL__/selftest.sh -o selftest.sh
#   bash selftest.sh              # check the installed agent
#   bash selftest.sh --uninstall  # also uninstall and check for leftovers
#
# Prints a report and saves it to /root/xmartguard-selftest-<time>.txt.
# The report contains no secrets (the identity key is never printed).
set -uo pipefail

UNINSTALL=0
[ "${1:-}" = "--uninstall" ] && UNINSTALL=1
[ "$(id -u)" -eq 0 ] || { echo "please run as root"; exit 1; }

REPORT=/root/xmartguard-selftest-$(date +%Y%m%d-%H%M%S).txt
exec > >(tee "$REPORT") 2>&1

pass=0; fail=0; warnc=0
check() { if eval "$2" >/dev/null 2>&1; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
warn()  { echo "WARN  $1"; warnc=$((warnc+1)); }
section() { echo; echo "===== $1 ====="; }

section "host"
echo "date:      $(date -u +%FT%TZ)"
echo "hostname:  $(hostname -f 2>/dev/null || hostname)"
. /etc/os-release 2>/dev/null && echo "os:        $PRETTY_NAME"
echo "kernel:    $(uname -r) $(uname -m)"
echo "systemd:   $(systemctl --version 2>/dev/null | head -1)"
[ -x /usr/local/cpanel/cpanel ] && echo "cpanel:    $(/usr/local/cpanel/cpanel -V 2>/dev/null)"
echo "selinux:   $(getenforce 2>/dev/null || echo n/a)"
command -v imunify360-agent >/dev/null && warn "Imunify360 is installed (fine for now; conflicts matter from M3/M4)"
command -v csf >/dev/null && echo "csf:       $(csf -v 2>/dev/null | head -1)"

section "agent install"
check "agent binary present"            '[ -x /usr/local/bin/xmartguard-agent ]'
echo "version:   $(/usr/local/bin/xmartguard-agent version 2>/dev/null)"
check "config present"                  '[ -f /etc/xmartguard/agent.json ]'
check "config mode 600"                 '[ "$(stat -c %a /etc/xmartguard/agent.json)" = 600 ]'
check "identity key mode 600"           '[ "$(stat -c %a /etc/xmartguard/identity.key)" = 600 ]'
check "config dir mode 700"             '[ "$(stat -c %a /etc/xmartguard)" = 700 ]'
check "install manifest present"        '[ -f /opt/xmartguard/manifest ]'
check "local uninstaller present"       '[ -x /opt/xmartguard/uninstall.sh ]'
echo "--- manifest"; grep -v '^#' /opt/xmartguard/manifest 2>/dev/null
echo "--- status"; /usr/local/bin/xmartguard-agent status 2>&1

section "service"
check "unit enabled"                    'systemctl is-enabled xmartguard-agent'
check "unit active"                     'systemctl is-active xmartguard-agent'
systemctl status xmartguard-agent --no-pager -l 2>&1 | head -15
echo "--- restart test"
systemctl restart xmartguard-agent; sleep 5
check "active after restart"            'systemctl is-active xmartguard-agent'
check "reconnected after restart"       'tail -n 20 /opt/xmartguard/logs/agent.log | grep -q "connected to portal"'
echo "--- memory/cpu of agent"
ps -o pid,rss,pcpu,etime,cmd -p "$(pgrep -d, -f 'xmartguard-agent run')" 2>/dev/null
echo "--- listening sockets of agent (should be none)"
ss -ltnp 2>/dev/null | grep xmartguard || echo "(none)"
check "agent opens no listening port"   '! ss -ltnp | grep -q xmartguard'

section "local control socket and panel plugins"
check "control socket answers"          '/usr/local/bin/xmartguard-agent call overview >/dev/null'
if [ -f /usr/local/cpanel/version ]; then
  check "WHM plugin installed"          '[ -x /usr/local/cpanel/whostmgr/docroot/cgi/xmartguard/index.cgi ]'
  check "WHM plugin registered"         '[ -f /var/cpanel/apps/xmartguard.conf ]'
  check "cPanel plugin installed"       '[ -f /usr/local/cpanel/base/frontend/jupiter/xmartguard/index.live.php ]'
fi
echo "--- IPDB"; /usr/local/bin/xmartguard-agent call ipdb.status 2>&1 | head -12

section "firewall"
command -v ipset >/dev/null && echo "ipset:     $(ipset version 2>/dev/null | head -1)" || warn "ipset is not installed"
echo "--- XMARTGUARD chain"; iptables -w -S XMARTGUARD 2>&1 | head -20
echo "--- INPUT jump"; iptables -w -S INPUT 2>/dev/null | grep XMARTGUARD || echo "(no jump)"
echo "--- ipsets"; ipset list -n 2>/dev/null | grep '^xg_' || echo "(none)"
nft list tables 2>/dev/null | grep -q 'inet xmartguard' && echo "nftables table inet xmartguard present"
command -v csf >/dev/null && echo "CSF present: $(csf -v 2>/dev/null | head -1)"
check "firewall rules loaded"          'iptables -w -C INPUT -j XMARTGUARD || nft list table inet xmartguard'

section "scanner"
ls -la /opt/xmartguard/ /opt/xmartguard/data/ 2>&1 | head
echo "inotify max_user_watches: $(cat /proc/sys/fs/inotify/max_user_watches)"
echo "ClamAV: $(ls /usr/local/cpanel/3rdparty/bin/clamdscan /usr/bin/clamdscan 2>/dev/null | head -1)"

section "portal connectivity"
PORTAL=$(sed -n 's/.*"server_url": *"\([^"]*\)".*/\1/p' /etc/xmartguard/agent.json 2>/dev/null)
echo "portal:    $PORTAL"
check "portal /api/health reachable"    "curl -fsS --max-time 15 '$PORTAL/api/health'"
check "agent binary downloadable"       "curl -fsS --max-time 30 -o /dev/null '$PORTAL/downloads/xmartguard-agent-linux-amd64.sha256'"

section "detected inventory"
/usr/local/bin/xmartguard-agent info 2>&1

section "agent log (last 30 lines)"
tail -n 30 /opt/xmartguard/logs/agent.log 2>&1
echo "--- install log"
tail -n 20 /opt/xmartguard/logs/install.log 2>&1

if [ "$UNINSTALL" -eq 1 ]; then
  section "uninstall"
  bash /opt/xmartguard/uninstall.sh 2>&1 || true
  section "leftovers after uninstall"
  check "binary removed"          '[ ! -e /opt/xmartguard/bin/xmartguard-agent ] && [ ! -L /usr/local/bin/xmartguard-agent ] && [ ! -L /usr/local/bin/xmartguard ]'
  check "config removed"          '[ ! -e /etc/xmartguard ]'
  check "state removed"           '[ ! -e /opt/xmartguard ] && [ ! -e /var/lib/xmartguard ]'
  check "plugins removed"         '[ ! -e /usr/local/cpanel/whostmgr/docroot/cgi/xmartguard ]'
  check "unit removed"            '[ ! -e /etc/systemd/system/xmartguard-agent.service ]'
  check "unit unknown to systemd" '! systemctl cat xmartguard-agent'
  check "no agent process"        '! pgrep -f "xmartguard-agent run"'
  check "no iptables chain"       '! iptables -w -S XMARTGUARD'
  check "no ipsets"               '! ipset list -n 2>/dev/null | grep -q "^xg_"'
  check "no nftables table"       '! nft list tables 2>/dev/null | grep -q "inet xmartguard"'
  echo "--- any file named *xmartguard* left on disk (outside /proc,/sys,/home):"
  find / -xdev \( -path /proc -o -path /sys -o -path /home -o -path /root \) -prune -o -iname '*xmartguard*' -print 2>/dev/null | head -20
fi

section "summary"
echo "passed: $pass   failed: $fail   warnings: $warnc"
echo "report saved to $REPORT"
echo "Send this whole output (or the report file) back to continue."
