#!/usr/bin/env bash
# XMart Guard agent uninstaller.
#
#   curl -fsSL __XG_PORTAL_URL__/uninstall.sh | bash
#   bash /opt/xmartguard/uninstall.sh [--dry-run] [--keep-logs] [--no-unenroll]
#
# Removes exactly what install.sh recorded in /opt/xmartguard/manifest
# (or /var/lib/xmartguard/manifest for installs before 0.3.0), including the
# cPanel/WHM plugins, then prints a residue report.
set -Euo pipefail

DRY=0
KEEP_LOGS=0
UNENROLL=1
for a in "$@"; do
  case "$a" in
    --dry-run)     DRY=1 ;;
    --keep-logs)   KEEP_LOGS=1 ;;
    --no-unenroll) UNENROLL=0 ;;
    -h|--help)     sed -n '2,9p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

HOME_DIR=/opt/xmartguard
STATE_DIR=$HOME_DIR
LOG_DIR=$HOME_DIR/logs
LEGACY_DIRS=(/var/lib/xmartguard /var/log/xmartguard)
MANIFEST=$STATE_DIR/manifest
[ -f "$MANIFEST" ] || MANIFEST=/var/lib/xmartguard/manifest
BIN=$HOME_DIR/bin/xmartguard-agent
[ -x "$BIN" ] || BIN=/usr/local/bin/xmartguard-agent
UNIT_NAME=xmartguard-agent.service

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_bld=$'\033[1m'; c_off=$'\033[0m'
[ -t 1 ] || { c_red=""; c_grn=""; c_ylw=""; c_bld=""; c_off=""; }
ok()   { printf '  %s✔%s %s\n' "$c_grn" "$c_off" "$*"; }
warn() { printf '  %s!%s %s\n' "$c_ylw" "$c_off" "$*"; }
run()  { if [ "$DRY" -eq 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi; }

[ "$(id -u)" -eq 0 ] || { echo "please run as root" >&2; exit 1; }

echo ""
echo "${c_bld}XMart Guard uninstaller${c_off}$([ "$DRY" -eq 1 ] && echo ' (dry run)')"
echo ""

# Paths we may remove. Only /etc/xmartguard, /opt/xmartguard, the pre-0.3.0
# /var/lib + /var/log dirs, /run/xmartguard, /usr/local/bin/xmartguard* and our
# unit are ever touched (panel plugin files are removed by the agent itself).
safe_path() {
  case "$1" in
    /etc/xmartguard|/etc/xmartguard/*) return 0 ;;
    /opt/xmartguard|/opt/xmartguard/*) return 0 ;;
    /run/xmartguard|/run/xmartguard/*) return 0 ;;
    /var/lib/xmartguard|/var/lib/xmartguard/*) return 0 ;;
    /var/log/xmartguard|/var/log/xmartguard/*) return 0 ;;
    /usr/local/bin/xmartguard|/usr/local/bin/xmartguard-agent) return 0 ;;
    /etc/systemd/system/xmartguard-agent.service) return 0 ;;
  esac
  return 1
}

FILES=(); DIRS=(); UNITS=()
if [ -f "$MANIFEST" ]; then
  while read -r kind path; do
    case "$kind" in
      file) FILES+=("$path") ;;
      dir)  DIRS+=("$path") ;;
      unit) UNITS+=("$path") ;;
    esac
  done < <(grep -v '^#' "$MANIFEST")
  ok "Loaded install manifest (${#FILES[@]} files, ${#DIRS[@]} directories)"
else
  warn "No install manifest found; removing the default locations."
  FILES=("$BIN" /usr/local/bin/xmartguard-agent /usr/local/bin/xmartguard)
  DIRS=(/etc/xmartguard "$HOME_DIR" "${LEGACY_DIRS[@]}")
  UNITS=("/etc/systemd/system/$UNIT_NAME")
fi

# 1. Tell the portal (best effort) before the identity key is deleted.
if [ "$UNENROLL" -eq 1 ] && [ -x "$BIN" ]; then
  if [ "$DRY" -eq 1 ]; then
    echo "  [dry-run] $BIN unenroll"
  elif "$BIN" unenroll >/dev/null 2>&1; then
    ok "Server removed from the portal"
  else
    warn "Could not reach the portal; remove the server from the portal manually if it is still listed."
  fi
fi

# 2. Stop and disable the service, then remove its firewall rules.
if systemctl list-unit-files "$UNIT_NAME" >/dev/null 2>&1 && systemctl cat "$UNIT_NAME" >/dev/null 2>&1; then
  run systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
  ok "Service stopped and disabled"
fi
if [ -x "$BIN" ]; then
  if [ "$DRY" -eq 1 ]; then echo "  [dry-run] $BIN cleanup"; else "$BIN" cleanup >/dev/null 2>&1 && ok "Firewall rules and WAF rules removed"; fi
fi
# cPanel/WHM plugins (before the binary that removes them is deleted).
if [ -x "$BIN" ] && { [ -d /usr/local/cpanel/whostmgr/docroot/cgi/xmartguard ] || [ -f /var/cpanel/apps/xmartguard.conf ]; }; then
  if [ "$DRY" -eq 1 ]; then echo "  [dry-run] $BIN panel uninstall"
  elif "$BIN" panel uninstall >/dev/null 2>&1; then ok "cPanel/WHM plugins removed"
  else warn "cPanel/WHM plugins could not be fully removed"; fi
fi
for u in "${UNITS[@]}"; do
  safe_path "$u" || { warn "skipping unexpected path $u"; continue; }
  [ -e "$u" ] && run rm -f "$u"
done
run systemctl daemon-reload || true
run systemctl reset-failed "$UNIT_NAME" >/dev/null 2>&1 || true

# 3. Remove files, then directories (deepest first).
for f in "${FILES[@]}"; do
  safe_path "$f" || { warn "skipping unexpected path $f"; continue; }
  if [ "$KEEP_LOGS" -eq 1 ]; then case "$f" in "$LOG_DIR"/*) continue ;; esac; fi
  { [ -e "$f" ] || [ -L "$f" ]; } && run rm -f "$f"
done
ok "Removed agent files"

# The copy of this script lives in STATE_DIR; bash has already read it.
DIRS+=(/run/xmartguard "$HOME_DIR")
# Never delete a portal checkout that an old portal setup left in /opt/xmartguard:
# remove only the agent's own entries there.
if [ -d "$HOME_DIR/.git" ]; then
  keep=()
  for d in "${DIRS[@]}"; do [ "$d" = "$HOME_DIR" ] || keep+=("$d"); done
  DIRS=("${keep[@]}" "$HOME_DIR/bin" "$HOME_DIR/data" "$HOME_DIR/logs")
  for f in "$HOME_DIR/manifest" "$HOME_DIR/uninstall.sh"; do [ -e "$f" ] && run rm -f "$f"; done
fi
for d in "${LEGACY_DIRS[@]}"; do [ -e "$d" ] && DIRS+=("$d"); done
mapfile -t SORTED < <(printf '%s\n' "${DIRS[@]}" | awk '{ print length, $0 }' | sort -rn | cut -d' ' -f2-)
for d in "${SORTED[@]}"; do
  [ -n "$d" ] || continue
  safe_path "$d" || { warn "skipping unexpected path $d"; continue; }
  if [ "$KEEP_LOGS" -eq 1 ] && [ "$d" = "$LOG_DIR" ]; then continue; fi
  if [ "$KEEP_LOGS" -eq 1 ] && [ "$d" = "$HOME_DIR" ]; then
    # Keep only the logs directory.
    [ -d "$d" ] && run find "$d" -mindepth 1 -maxdepth 1 ! -name logs -exec rm -rf -- {} +
    continue
  fi
  [ -d "$d" ] && run rm -rf -- "$d"
done
ok "Removed configuration and state directories"

# 4. Residue report.
[ "$DRY" -eq 1 ] && { echo ""; echo "Dry run complete; nothing was changed."; exit 0; }
LEFT=()
KEEP_HOME=()
[ "$KEEP_LOGS" -eq 0 ] && [ ! -d "$HOME_DIR/.git" ] && KEEP_HOME=("$HOME_DIR")
for p in "$BIN" /usr/local/bin/xmartguard-agent /usr/local/bin/xmartguard /etc/xmartguard "${KEEP_HOME[@]}" /run/xmartguard \
         /usr/local/cpanel/whostmgr/docroot/cgi/xmartguard /usr/local/cpanel/base/frontend/jupiter/xmartguard \
         "${LEGACY_DIRS[@]}" /etc/systemd/system/$UNIT_NAME; do
  { [ -e "$p" ] || [ -L "$p" ]; } && LEFT+=("$p")
done
[ "$KEEP_LOGS" -eq 0 ] && [ -e "$LOG_DIR" ] && LEFT+=("$LOG_DIR")
for w in /etc/apache2/conf.d/includes/xmartguard-waf.conf /etc/apache2/conf-available/xmartguard-waf.conf /etc/httpd/conf.d/xmartguard-waf.conf; do
  [ -e "$w" ] && LEFT+=("WAF include $w")
done
if pgrep -f "$BIN run" >/dev/null 2>&1; then LEFT+=("running process: $BIN"); fi
if command -v iptables >/dev/null 2>&1 && iptables -w -S XMARTGUARD >/dev/null 2>&1; then LEFT+=("iptables chain XMARTGUARD"); fi
if command -v ipset >/dev/null 2>&1 && ipset list -n 2>/dev/null | grep -q '^xg_'; then LEFT+=("ipset sets xg_*"); fi
if command -v nft >/dev/null 2>&1 && nft list tables 2>/dev/null | grep -q 'inet xmartguard'; then LEFT+=("nftables table inet xmartguard"); fi

echo ""
if [ ${#LEFT[@]} -eq 0 ]; then
  echo "${c_grn}${c_bld}XMart Guard was removed completely. Nothing was left behind.${c_off}"
else
  echo "${c_red}${c_bld}Uninstall finished, but these items remain:${c_off}"
  printf '   - %s\n' "${LEFT[@]}"
  exit 1
fi
[ "$KEEP_LOGS" -eq 1 ] && echo "Logs kept in $LOG_DIR"
echo ""
