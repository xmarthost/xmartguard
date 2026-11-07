#!/bin/bash
# xPGuard daily health check (read-only: it changes nothing on the server).
#
#   curl -fsSL https://raw.githubusercontent.com/xmarthost/xmartguard/main/deploy/xpguard-health.sh | bash
#   (or: bash xpguard-health.sh [hours], default the last 24 hours)
#
# It reports, for the last HOURS:
#   1. the server: load, memory, swap activity, disk, connections
#   2. the xPGuard agent: version, running, restarts, warnings and errors
#   3. LiteSpeed/Apache restarts, each with its most likely cause
#      (xPGuard WAF reload, agent update, LiteSpeed licence cron, log
#      rotation, cPanel/other)
#   4. websites answering 500/502/503/504/508, and the addresses behind them
#   5. PHP limits (LSAPI max children) and CloudLinux account limits
#   6. crashes and out-of-memory kills
#   7. xPGuard firewall, WAF and CAPTCHA state
#   8. xPGuard CMS updates and scanner problems
# Paste the whole output back for review.

HOURS="${1:-24}"
case "$HOURS" in ''|*[!0-9]*) HOURS=24 ;; esac
export LC_ALL=C
NOW=$(date +%s)
SINCE=$((NOW - HOURS * 3600))
SINCE_ISO=$(date -d "@$SINCE" +%Y-%m-%dT%H:%M)
# (The XG_* variables are for its tests.)
AGENT_LOG=${XG_AGENT_LOG:-/opt/xpguard/logs/agent.log}
WAF_DIR=${XG_WAF_DIR:-/etc/xpguard/waf}
LSRESTART=${XG_LSRESTART:-/usr/local/lsws/logs/lsrestart.log}
ERRLOG=${XG_ERRLOG:-/usr/local/apache/logs/error_log}
STDERR=${XG_STDERR:-/usr/local/apache/logs/stderr.log}
DOMLOGS=${XG_DOMLOGS:-/etc/apache2/logs/domlogs}
T() { timeout "${1}" "${@:2}" 2>/dev/null; }
h() { printf '\n===== %s =====\n' "$*"; }

# agent.log lines of the window (its times are ISO, local zone).
agent_lines() { [ -r "$AGENT_LOG" ] && awk -v s="$SINCE_ISO" 'match($0,/time=[0-9T:-]+/){t=substr($0,RSTART+5,16); if(t>=s) print}' "$AGENT_LOG"; }

printf 'xPGuard health check: %s  (last %s hours, from %s)\n' "$(hostname)" "$HOURS" "$(date -d "@$SINCE" '+%F %T %Z')"

# ---------------------------------------------------------------- 1. server
h "1. SERVER"
echo "uptime: $(uptime)"
echo "cpus: $(nproc)"
free -m | sed 's/^/  /'
echo "-- swap activity (si/so near 0 = swap not slowing the server):"
T 10 vmstat 1 3 | sed 's/^/  /'
echo "-- disk:"
df -hP 2>/dev/null | awk 'NR==1 || ($5+0)>=80 {print "  "$0}'
echo "-- connections: established=$(T 10 ss -Htn state established | wc -l)  conntrack=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null)/$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)"
echo "-- PHP processes: lsphp=$(pgrep -c lsphp)  php-fpm=$(pgrep -c php-fpm)"

# ---------------------------------------------------------------- 2. agent
h "2. XPGUARD AGENT"
if command -v xpguard-agent >/dev/null 2>&1; then
  echo "version: $(xpguard-agent version 2>/dev/null | head -1)"
  T 10 xpguard-agent status | grep -E '"(status|portal|server_id)"' | sed 's/^/  /'
fi
echo "service: $(systemctl is-active xpguard-agent 2>/dev/null)  since $(systemctl show xpguard-agent -p ActiveEnterTimestamp --value 2>/dev/null)  restarts(total)=$(systemctl show xpguard-agent -p NRestarts --value 2>/dev/null)"
echo "-- agent starts in the window (updates or restarts):"
agent_lines | grep -E 'msg="(starting xpguard-agent|agent updated; restarting)"' | sed -E 's/^time=([^ ]+).*msg="([^"]*)".*(version|new_version)=([^ ]+).*/  \1  \2 \4/' | tail -15
echo "-- warnings and errors by message (window):"
agent_lines | grep -E 'level=(WARN|ERROR)' | grep -oE 'msg="[^"]*"' | sort | uniq -c | sort -rn | head -25 | sed 's/^/  /'
echo "-- last 10 errors (window):"
agent_lines | grep 'level=ERROR' | tail -10 | cut -c1-300 | sed 's/^/  /'
echo "-- agent memory: $(ps -o rss= -C xpguard-agent 2>/dev/null | awk '{s+=$1} END {printf "%d MB", s/1024}')"

# ---------------------------------------------------------------- 3. restarts
h "3. WEB SERVER RESTARTS (with likely cause)"
# xPGuard's own reloads (agent 0.24.46+ logs each with the files that changed).
agent_lines | grep 'msg="web server reloaded for the WAF rules"' | sed -E 's/^time=([^ ]+).*changed=("[^"]*"|[^ ]*).*urgent=([a-z]+).*/\1 \2 urgent=\3/' > /tmp/.xg_reloads.$$
# Agent starts (an update restarts the agent, which may reload once).
agent_lines | grep 'msg="starting xpguard-agent"' | sed -E 's/^time=([^ ]+).*/\1/' > /tmp/.xg_starts.$$
CSP=no; [ -f /etc/cron.d/CSPLiteSpeed ] && CSP=yes
if [ -r "$LSRESTART" ]; then
  echo "(LiteSpeed's own log $LSRESTART; CSPLiteSpeed cron present: $CSP)"
  # "restart, LSWS running: 1" followed by the date line.
  # (one restart can write two entries in the same second: counted once)
  tail -n 4000 "$LSRESTART" | awk '/^restart, LSWS running/{getline d; if (d != last) print d; last = d}' | while read -r d; do
    t=$(date -d "$d" +%s 2>/dev/null) || continue
    [ "$t" -ge "$SINCE" ] || continue
    cause=""
    while read -r r rest; do
      rt=$(date -d "${r%%.*}" +%s 2>/dev/null) || continue
      if [ $((t - rt)) -ge -90 ] && [ $((t - rt)) -le 90 ]; then cause="xPGuard WAF reload ($rest)"; break; fi
    done < /tmp/.xg_reloads.$$
    if [ -z "$cause" ]; then
      while read -r s; do
        st=$(date -d "${s%%.*}" +%s 2>/dev/null) || continue
        if [ $((t - st)) -ge 0 ] && [ $((t - st)) -le 150 ]; then cause="xPGuard agent start/update (rules written at start)"; break; fi
      done < /tmp/.xg_starts.$$
    fi
    m=$(date -d "@$t" +%M); hh=$(date -d "@$t" +%H)
    if [ -z "$cause" ] && [ "$hh$m" -ge 0000 ] && [ "$hh$m" -le 0005 ]; then cause="midnight (daily log rotation, likely)"; fi
    if [ -z "$cause" ] && [ "$CSP" = yes ] && { { [ "${m#0}" -ge 2 ] && [ "${m#0}" -le 9 ]; } || { [ "${m#0}" -ge 40 ] && [ "${m#0}" -le 46 ]; }; }; then cause="CSPLiteSpeed cron minute (:04 / :43), likely"; fi
    [ -z "$cause" ] && cause="cPanel or other (not xPGuard: no xPGuard reload within 90 s)"
    printf '  %s  %s\n' "$(date -d "@$t" '+%F %T')" "$cause"
  done | tee /tmp/.xg_rs.$$
  echo "(before agent 0.24.46 xPGuard did not log its reloads: older xPGuard reloads show as 'cPanel or other')"
  echo "-- totals: $(wc -l < /tmp/.xg_rs.$$) restarts; by cause:"
  sed -E 's/^  [0-9-]+ [0-9:]+  //; s/ \(.*//' /tmp/.xg_rs.$$ | sort | uniq -c | sort -rn | sed 's/^/  /'
else
  echo "no $LSRESTART (not LiteSpeed?)"
  grep -aE 'resuming normal operations|Graceful restart|shutting down gracefully' "$ERRLOG" 2>/dev/null | tail -20 | sed 's/^/  /'
fi
echo "-- xPGuard reloads logged by the agent in the window: $(wc -l < /tmp/.xg_reloads.$$)"
sed 's/^/  /' /tmp/.xg_reloads.$$ | tail -15
rm -f /tmp/.xg_reloads.$$ /tmp/.xg_starts.$$ /tmp/.xg_rs.$$

# ---------------------------------------------------------------- 4. 5xx
h "4. WEBSITES ANSWERING 5xx (window)"
if [ -d "$DOMLOGS" ]; then
  D1=$(date +%d/%b/%Y); D0=$(date -d "-1 day" +%d/%b/%Y)
  find "$DOMLOGS" -maxdepth 2 -type f -mmin -$((HOURS * 60 + 60)) ! -name '*.bkup' ! -name '*bytes_log' ! -name '*.offset' 2>/dev/null > /tmp/.xg_dl.$$
  : > /tmp/.xg_5xx.$$
  while read -r f; do
    T 30 awk -v a="[$D0" -v b="[$D1" -v site="$(basename "$f" | sed 's/-ssl_log$//')" '(index($0,a) || index($0,b)) && match($0,/" (5[0-9][0-9]) /){c=substr($0,RSTART+2,3); print site, c, $1}' "$f" >> /tmp/.xg_5xx.$$
  done < /tmp/.xg_dl.$$
  echo "-- by website and code (top 20):"
  awk '{print $1, $2}' /tmp/.xg_5xx.$$ | sort | uniq -c | sort -rn | head -20 | sed 's/^/  /'
  echo "-- 503/508/509 (overload, account limits, 509 = account bandwidth used up) by website (top 10):"
  awk '$2=="503"||$2=="508"||$2=="509"{print $1, $2}' /tmp/.xg_5xx.$$ | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'
  echo "-- addresses getting the most 5xx (top 15):"
  awk '{print $3}' /tmp/.xg_5xx.$$ | sort | uniq -c | sort -rn | head -15 | sed 's/^/  /'
  rm -f /tmp/.xg_dl.$$ /tmp/.xg_5xx.$$
fi

# ---------------------------------------------------------------- 5. limits
h "5. PHP AND ACCOUNT LIMITS"
if [ -r "$STDERR" ]; then
  tail -c 300000000 "$STDERR" > /tmp/.xg_se.$$
  echo "LSAPI 'Reached max children' in the last 300 MB of stderr.log: $(grep -ac 'Reached max children' /tmp/.xg_se.$$)"
  echo "-- by account, where the log line names it (top 10):"
  grep -a 'Reached max children' /tmp/.xg_se.$$ | tail -50000 | grep -aoE '/home[0-9]*/[a-z0-9_]+' | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'
  rm -f /tmp/.xg_se.$$
fi
if command -v lveinfo >/dev/null 2>&1; then
  echo "-- CloudLinux accounts hitting limits (EPf entry processes, PMemF memory, NprocF processes, last day):"
  T 60 lveinfo --period=1d --by-fault=any --display-username --limit=10 --columns=ID,EPf,PMemF,VMemF,NprocF,aCPU,mPMem,lPMem 2>/dev/null | sed 's/^/  /' \
    || T 60 lveinfo --period=1d --by-fault=any --display-username --limit=10 | sed 's/^/  /'
fi

# ---------------------------------------------------------------- 6. crashes
h "6. CRASHES AND OUT-OF-MEMORY"
echo "-- web server crashes (signal 6/11, not the 'Core dump is enabled' notice):"
grep -aE 'signal (6|11)|Segmentation|exited abnormally' "$ERRLOG" 2>/dev/null | grep -v 'Core dump is enabled' | tail -5 | sed 's/^/  /'
echo "-- out-of-memory kills (window):"
T 20 journalctl -k --since "@$SINCE" --no-pager 2>/dev/null | grep -i 'killed process' | sed -E 's/.*Killed process [0-9]+ \(([^)]+)\).*UID:([0-9]+).*/\1 uid=\2/' | sort | uniq -c | sort -rn | head -10 | while read -r n p u; do echo "  $n x $p ${u} ($(getent passwd "${u#uid=}" | cut -d: -f1))"; done

# ---------------------------------------------------------------- 7. xPGuard protection
h "7. XPGUARD FIREWALL, WAF, CAPTCHA"
if command -v ipset >/dev/null 2>&1; then
  for s in xg_ipdb4 xg_tban4 xg_deny4 xg_cpass4 xg_exempt4 xg_allow4; do
    printf '  %-11s %s entries\n' "$s" "$(ipset list -t "$s" 2>/dev/null | awk -F': ' '/Number of entries/{print $2}')"
  done
fi
echo "-- WAF rules: $(ls "$WAF_DIR"/*.conf 2>/dev/null | wc -l) conf files, rules.conf changed $(stat -c %y "$WAF_DIR/rules.conf" 2>/dev/null | cut -c1-19)"
echo "-- WAF self-test: $(T 30 xpguard-agent call waf.status | tr -d ' \n' | grep -oE '"self_test":\{"at":[0-9]+,"ok":(true|false),"status":[0-9]+' | sed -E 's/.*"at":([0-9]+),"ok":([a-z]+),"status":([0-9]+)/ok=\2 status=\3 at=\1/')"
HOOK=$(grep -ls 'xpguard' /etc/apache2/conf.d/modsec/modsec2.user.conf /etc/apache2/conf-enabled/*.conf /etc/httpd/conf.d/*.conf /usr/local/lsws/conf/*.conf 2>/dev/null | head -1)
echo "-- WAF include: ${HOOK:-MISSING (the web server does not load the xPGuard rules)}"
echo "-- CAPTCHA settings: $(grep -oE '"(central|central_mode|central_url|login_gate|hosting_login)": *("[^"]*"|true|false)' /etc/xpguard/settings.json 2>/dev/null | tr '\n' ' ')"
echo "-- site page alias: $( [ -f /etc/apache2/conf.d/xpguard-verify.conf ] && head -2 /etc/apache2/conf.d/xpguard-verify.conf | tail -1 || echo none)"
HN=$(hostname -f 2>/dev/null)
echo "-- site page on the hostname: HTTP $(T 15 curl -sk -o /dev/null -w '%{http_code}' "https://$HN/xpguard-verify/?s=x&ip=127.0.0.1&h=$HN&u=/")"
echo "-- CAPTCHA in the window: passes=$(agent_lines | grep -c 'captcha solved')  withdrawn pass values=$(agent_lines | grep -c 'value withdrawn')  login-attack notices=$(agent_lines | grep -c 'login attack from many addresses')"
echo "-- portal connection lost (window): $(agent_lines | grep -c 'portal connection lost')"

# ---------------------------------------------------------------- 8. CMS and scanner
h "8. XPGUARD CMS AND SCANNER"
echo "-- CMS updates (window): ok=$(agent_lines | grep -c 'msg="CMS automatic action"')  failed=$(agent_lines | grep -c 'CMS automatic action failed')  no-update=$(agent_lines | grep -c 'has no update WordPress can install')"
echo "-- CMS failure reasons (top 5):"
agent_lines | grep 'CMS automatic action failed' | grep -oE '(Error|Warning): [^\\"]{0,90}' | sed -E 's/[0-9a-zA-Z]{16}"?$//; s#/home[0-9]*/[^/]+/#/home/<user>/#g' | sort | uniq -c | sort -rn | head -5 | sed 's/^/  /'
echo "-- scanner: quarantined=$(agent_lines | grep -c 'msg="file quarantined"')  keeps-coming-back=$(agent_lines | grep -c 'keeps coming back')  quarantine-failed=$(agent_lines | grep -c 'quarantine failed')  queue-overflow=$(agent_lines | grep -c 'queue overflowed')"
echo "-- process and cron monitor (last 8 events):"
T 20 xpguard-agent call monitor.events '{"limit":8}' | tr -d '\n' | sed -E 's/": +/":/g; s/, +"/,"/g' | grep -oE '"at":[0-9]+,"kind":"[a-z]+","user":"[^"]*","subject":"[^"]{0,110}|"action":"[a-z]+"' | paste -d' ' - - | sed -E 's/"at":([0-9]+)/\1/' | while read -r at rest; do echo "  $(date -d "@$at" '+%F %T') $rest"; done

printf '\nDone. Nothing was changed on this server.\n'
