#!/usr/bin/env bash
# Removes an xPGuard portal that setup-almalinux.sh installed on a server by
# mistake (for example on a server that should only run the agent). It only
# removes what the setup created, and checks before every step:
#   - the portal's Docker containers, volumes and /opt/xmartguard-portal
#   - the cPanel account the setup created for the portal's domain
#     (only an account named xmartgd/xmartgN whose main domain is that domain)
#   - the Apache proxy includes, the CSF and nftables hooks for Docker
#   - with --remove-docker: Docker itself, if no other container uses it
# The xPGuard agent (/opt/xpguard) is not touched.
#
#   bash remove-portal.sh --domain app.xpguard.org [--remove-docker] [--yes]
set -u
DOMAIN="" REMOVE_DOCKER=0 YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --remove-docker) REMOVE_DOCKER=1; shift ;;
    --yes) YES=1; shift ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done
DIR=/opt/xmartguard-portal
ok()   { printf '    \033[32m✔\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
[ -n "$DOMAIN" ] || { echo "usage: bash remove-portal.sh --domain app.xpguard.org [--remove-docker] [--yes]"; exit 2; }

# What will be removed.
CPUSER=""
if [ -x /usr/local/cpanel/scripts/whoowns ]; then
  U=$(/usr/local/cpanel/scripts/whoowns "$DOMAIN" 2>/dev/null || true)
  if [ -n "$U" ] && [ -f "/var/cpanel/users/$U" ]; then
    MAIN=$(sed -n 's/^DNS=//p' "/var/cpanel/users/$U" | head -1)
    if [[ "$U" =~ ^xmartg(d|[0-9]+)$ ]] && [ "$MAIN" = "$DOMAIN" ]; then
      CPUSER=$U
    else
      warn "$DOMAIN belongs to cPanel account '$U' (main domain $MAIN), which the setup did not create: it is kept"
    fi
  fi
fi
step "This will remove"
[ -d "$DIR" ] && echo "    - the portal in $DIR (containers, database volume, images)" || echo "    - (no portal directory $DIR)"
[ -n "$CPUSER" ] && echo "    - cPanel account '$CPUSER' ($DOMAIN, with its DNS zone and aliases)"
[ "$REMOVE_DOCKER" = 1 ] && echo "    - Docker, if no other container is left"
echo "    The xPGuard agent is not touched."
if [ "$YES" != 1 ]; then
  read -r -p "Continue? [y/N] " a
  [ "$a" = y ] || [ "$a" = Y ] || { echo "nothing changed"; exit 0; }
fi

if [ -d "$DIR/deploy" ] && command -v docker >/dev/null 2>&1; then
  step "Stopping and removing the portal containers"
  (cd "$DIR/deploy" && docker compose --profile caddy down -v --remove-orphans --rmi local) && ok "containers and volumes removed" || warn "docker compose down failed"
fi
rm -rf "$DIR" && ok "removed $DIR"

if [ -n "$CPUSER" ]; then
  step "Removing cPanel account '$CPUSER'"
  rm -rf "/etc/apache2/conf.d/userdata/std/2_4/$CPUSER" "/etc/apache2/conf.d/userdata/ssl/2_4/$CPUSER"
  if whmapi1 --output=json removeacct username="$CPUSER" keepdns=0 2>&1 | grep -q '"result":1'; then
    ok "account, DNS zone and aliases removed"
  else
    warn "could not remove the account: remove '$CPUSER' in WHM » Terminate Accounts"
  fi
  /usr/local/cpanel/scripts/rebuildhttpdconf >/dev/null 2>&1 && /usr/local/cpanel/scripts/restartsrv_httpd >/dev/null 2>&1 && ok "Apache configuration rebuilt"
fi

step "Removing the Docker firewall hooks"
CSFPOST=/usr/local/csf/bin/csfpost.sh
if [ -f "$CSFPOST" ] && grep -q "xPGuard portal: recreate Docker" "$CSFPOST"; then
  sed -i '/xPGuard portal: recreate Docker/d' "$CSFPOST" && ok "CSF hook removed"
fi
if [ -f /etc/systemd/system/nftables.service.d/xpguard-docker.conf ]; then
  rm -f /etc/systemd/system/nftables.service.d/xpguard-docker.conf
  rmdir /etc/systemd/system/nftables.service.d 2>/dev/null || true
  systemctl daemon-reload && ok "nftables hook removed"
fi

if [ "$REMOVE_DOCKER" = 1 ] && command -v docker >/dev/null 2>&1; then
  step "Removing Docker"
  if [ -n "$(docker ps -aq 2>/dev/null)" ]; then
    warn "other containers exist ($(docker ps -a --format '{{.Names}}' | tr '\n' ' ')): Docker is kept"
  else
    systemctl disable --now docker.socket docker containerd >/dev/null 2>&1 || true
    dnf -y -q remove docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1 || true
    rm -rf /var/lib/docker /var/lib/containerd /etc/yum.repos.d/docker-ce.repo
    ok "Docker removed"
    # Docker's own firewall chains go with a firewall reload.
    if command -v csf >/dev/null 2>&1; then csf -r >/dev/null 2>&1 && ok "CSF reloaded"; fi
    if systemctl is-active -q xpguard-agent; then systemctl restart xpguard-agent && ok "xPGuard agent restarted (firewall rules rebuilt)"; fi
  fi
fi

step "Check"
echo "    $DOMAIN resolves to: $(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}')"
curl -fsS --max-time 10 "https://$DOMAIN/api/health" >/dev/null 2>&1 && ok "the real portal at https://$DOMAIN answers" || warn "https://$DOMAIN did not answer from here (check from another place)"
