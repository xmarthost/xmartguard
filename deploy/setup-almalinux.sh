#!/usr/bin/env bash
# One-shot xPGuard PORTAL setup for AlmaLinux / Rocky / RHEL / CloudLinux 9.
#
#   bash setup-almalinux.sh --domain app.xpguard.org --email you@example.com [--branch BRANCH] [--token GITHUB_TOKEN]
#                           [--captcha-domain captcha.xpguard.org | none]
#
# The CAPTCHA page for suspicious visitors of the websites' login pages is
# served by the portal on its own domain, by default captcha.<parent domain>
# (app.xpguard.org -> captcha.xpguard.org). Point that name at this server.
#
# The AI scanner uses free AI APIs (Google Gemini, Groq, OpenRouter, ...)
# whose keys are added in the portal under "AI Scanner"; no model runs on
# this server. A local model installed by 0.5.x (Ollama) is removed.
#
# Works on a plain VPS and on a server that already runs cPanel/WHM:
#   - plain VPS:  Caddy container serves ports 80/443 with automatic HTTPS.
#   - cPanel:     Apache keeps ports 80/443. The domain is attached to a cPanel
#                 account (created if needed), AutoSSL issues the certificate
#                 and an Apache include proxies the domain to the portal on
#                 127.0.0.1:18080. Other sites on the server are not touched.
# Safe to re-run: it updates the code and restarts the stack.
set -Eeuo pipefail

DOMAIN=""; EMAIL=""; BRANCH="main"; TOKEN="${GITHUB_TOKEN:-}"; CAPTCHA_DOMAIN=""
REPO="github.com/xmarthost/xmartguard.git"
DIR=/opt/xmartguard-portal
# Portal setups before 0.3.0 used /opt/xmartguard, which now belongs to the agent.
OLD_DIR=/opt/xmartguard
PORTAL_PORT=18080

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --email)  EMAIL="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --token)  TOKEN="$2"; shift 2 ;;
    --captcha-domain) CAPTCHA_DOMAIN="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    --ai|--ai-url|--ai-model) echo "note: $1 is no longer used (AI keys are set in the portal)"; shift 2 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m✔\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mERROR: %s\033[0m\n' "$*"; exit 1; }
trap 'die "setup failed at line $LINENO"' ERR

[ "$(id -u)" -eq 0 ] || die "run as root"
[ -n "$DOMAIN" ] && [ -n "$EMAIL" ] || die "usage: bash setup-almalinux.sh --domain app.xpguard.org --email you@example.com"
. /etc/os-release
case "${ID}${ID_LIKE:-}" in *rhel*|*almalinux*|*rocky*|*centos*|*cloudlinux*) ;; *) die "this script is for AlmaLinux/Rocky/RHEL/CloudLinux";; esac

if [ -x /usr/local/cpanel/cpanel ]; then
  MODE=cpanel
elif ss -ltnH '( sport = :80 or sport = :443 )' 2>/dev/null | grep -q . && ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q caddy; then
  die "ports 80/443 are used by another web server (not cPanel). Stop it or put the portal behind it manually (proxy to 127.0.0.1:$PORTAL_PORT)."
else
  MODE=caddy
fi
echo "mode: $MODE"
if [ -z "$CAPTCHA_DOMAIN" ]; then
  # captcha.<parent domain>, when the portal runs on a subdomain.
  if [ "$(tr -cd . <<<"$DOMAIN" | wc -c)" -ge 2 ]; then CAPTCHA_DOMAIN="captcha.${DOMAIN#*.}"; else CAPTCHA_DOMAIN=none; fi
fi
[ "$CAPTCHA_DOMAIN" = "$DOMAIN" ] && CAPTCHA_DOMAIN=none

step "Checking DNS for $DOMAIN"
MYIP=$(curl -4 -fsS --max-time 10 https://api.ipify.org || true)
DNSIP=$(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}' || true)
echo "    this server: ${MYIP:-unknown}   $DOMAIN -> ${DNSIP:-not resolving}"
if [ -z "$DNSIP" ] || [ "$DNSIP" != "$MYIP" ]; then
  # A server that only runs the agent: the portal is installed elsewhere.
  # Running this here by mistake would create a cPanel account for the
  # portal's domain (and Docker); refuse unless asked explicitly.
  if [ ! -d "$DIR" ] && [ "${FORCE:-0}" != 1 ] && { [ -n "$DNSIP" ] || [ -x /opt/xpguard/bin/xpguard-agent ]; }; then
    die "$DOMAIN points at ${DNSIP:-another server}, not this server (${MYIP:-unknown}), and the portal is not installed here.
       This looks like a server that only runs the xPGuard agent: update agents from the portal instead
       (Servers » Update agent). To install the portal on this server anyway, add --force."
  fi
  warn "$DOMAIN does not point at this server yet; HTTPS will not work until the A record is $MYIP."
fi

step "Installing packages and Docker"
dnf -y -q install git curl dnf-plugins-core openssl >/dev/null 2>&1 || dnf -y install git curl dnf-plugins-core openssl
# A "docker" command alone is not enough: podman-docker provides one without
# the Docker service. Install Docker CE unless its service really exists.
if ! systemctl list-unit-files docker.service 2>/dev/null | grep -q '^docker.service'; then
  if rpm -q podman-docker >/dev/null 2>&1 || rpm -q runc >/dev/null 2>&1; then
    warn "removing podman-docker/runc (they conflict with Docker CE)"
    dnf -y -q remove podman-docker runc >/dev/null 2>&1 || true
  fi
  dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo >/dev/null
  if ! dnf -y install --allowerasing docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
    die "Docker CE could not be installed (see the dnf output above)"
  fi
fi
# podman-docker leaves DOCKER_HOST=unix:///run/podman/podman.sock in login
# shells (and a /run/docker.sock symlink to it); talk to the real daemon.
case "${DOCKER_HOST:-}" in *podman*) unset DOCKER_HOST ;; esac
rm -f /etc/profile.d/podman-docker.sh /etc/profile.d/podman-docker.csh
if [ -L /run/docker.sock ] && ! systemctl is-active -q docker; then rm -f /run/docker.sock; fi
systemctl enable --now docker >/dev/null
docker context use default >/dev/null 2>&1 || true
docker compose version >/dev/null 2>&1 || dnf -y install docker-compose-plugin
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info >/dev/null 2>&1 || die "the Docker daemon is not answering (systemctl status docker)"
ok "$(docker --version)"

# Building the image needs ~2 GB RAM; add swap on small servers.
MEM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
if [ "$MEM_MB" -lt 3000 ] && ! swapon --show | grep -q .; then
  step "Adding 2 GB swap (RAM is ${MEM_MB} MB)"
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
fi

if [ "$MODE" = caddy ]; then
  step "Opening firewall ports 80 and 443"
  if systemctl is-active --quiet firewalld; then
    firewall-cmd -q --permanent --add-service=http --add-service=https && firewall-cmd -q --reload
    ok "firewalld updated"
  else
    warn "firewalld not running; make sure ports 80/443 are open at your provider"
  fi
fi

if [ ! -e "$DIR" ] && [ -d "$OLD_DIR/.git" ] && [ -f "$OLD_DIR/deploy/docker-compose.yml" ]; then
  step "Moving the portal from $OLD_DIR to $DIR"
  # Same compose project name ("deploy"), so the database volume is kept.
  (cd "$OLD_DIR/deploy" && docker compose down --remove-orphans >/dev/null 2>&1) || true
  mkdir -p "$DIR"
  shopt -s dotglob
  for f in "$OLD_DIR"/*; do
    case "$(basename "$f")" in bin|data|logs|manifest|uninstall.sh|.install.*) continue ;; esac
    mv "$f" "$DIR/"
  done
  shopt -u dotglob
  rmdir "$OLD_DIR" 2>/dev/null || true
  ok "portal moved; its data and settings are unchanged"
fi

step "Getting the code ($BRANCH)"
URL="https://$REPO"
[ -n "$TOKEN" ] && URL="https://x-access-token:${TOKEN}@$REPO"
if [ -d "$DIR/.git" ]; then
  git -C "$DIR" remote set-url origin "$URL"
  git -C "$DIR" fetch -q origin "$BRANCH"
  git -C "$DIR" checkout -q -B "$BRANCH" "origin/$BRANCH"
else
  git clone -q --branch "$BRANCH" "$URL" "$DIR"
fi
# Do not leave the token on disk.
git -C "$DIR" remote set-url origin "https://$REPO"
ok "$(git -C "$DIR" log --oneline -1)"

step "Writing configuration"
ENV="$DIR/deploy/.env"
if [ ! -f "$ENV" ]; then
  cat >"$ENV" <<EOF
DOMAIN=$DOMAIN
POSTGRES_PASSWORD=$(openssl rand -hex 24)
ADMIN_EMAIL=$EMAIL
ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)
PORTAL_PORT=$PORTAL_PORT
EOF
  chmod 600 "$ENV"
  ok "created $ENV"
else
  sed -i "s/^DOMAIN=.*/DOMAIN=$DOMAIN/" "$ENV"
  grep -q '^PORTAL_PORT=' "$ENV" || echo "PORTAL_PORT=$PORTAL_PORT" >>"$ENV"
  ok "kept existing $ENV"
fi
# The CAPTCHA page's address (empty: served on the portal's own domain).
sed -i '/^CAPTCHA_DOMAIN=/d; /^CAPTCHA_URL=/d' "$ENV"
if [ "$CAPTCHA_DOMAIN" != none ]; then
  echo "CAPTCHA_DOMAIN=$CAPTCHA_DOMAIN" >>"$ENV"
  echo "CAPTCHA_URL=https://$CAPTCHA_DOMAIN" >>"$ENV"
else
  echo "CAPTCHA_URL=https://$DOMAIN" >>"$ENV"
fi
PORTAL_PORT=$(sed -n 's/^PORTAL_PORT=//p' "$ENV")

# ------------------------------------------------------------------ AI
# 0.6 uses free AI APIs configured in the portal. Drop the 0.5 local model
# settings; the model container and its data are removed after the restart.
for k in OLLAMA_URL OLLAMA_MODEL OLLAMA_LOCAL AI_CONCURRENCY; do sed -i "/^$k=/d" "$ENV"; done

remove_local_ai() {
  local removed=0
  # The portal's compose project is "deploy": deploy-ollama-1 / deploy_ollama.
  if docker ps -a --format '{{.Names}}' | grep -Eq '^deploy[-_]ollama[-_]'; then
    docker ps -a --format '{{.Names}}' | grep -E '^deploy[-_]ollama[-_]' | xargs -r docker rm -f >/dev/null 2>&1 || true
    removed=1
  fi
  if docker volume inspect deploy_ollama >/dev/null 2>&1; then
    docker volume rm deploy_ollama >/dev/null 2>&1 || true
    removed=1
  fi
  if docker image inspect ollama/ollama:latest >/dev/null 2>&1; then
    docker image rm ollama/ollama:latest >/dev/null 2>&1 || true
    removed=1
  fi
  # A native install made by 0.5's setup-ai.sh (it left this marker).
  if [ -f /etc/systemd/system/ollama.service.d/xmartguard.conf ]; then
    systemctl disable --now ollama >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/ollama.service
    rm -rf /etc/systemd/system/ollama.service.d
    systemctl daemon-reload
    rm -rf /usr/local/bin/ollama /usr/local/lib/ollama /usr/share/ollama
    if id ollama >/dev/null 2>&1; then userdel ollama >/dev/null 2>&1 || true; fi
    removed=1
  fi
  if [ "$removed" = 1 ]; then ok "removed the local AI model (Ollama) and its downloaded files"; fi
  return 0
}

step "Building and starting the portal (first build takes several minutes)"
cd "$DIR/deploy"
# CSF (`csf -r`) flushes Docker's firewall chains; without them no container
# can publish its port. Recreate them first (restarts Docker only if needed).
if ! iptables -w -t nat -n -L DOCKER >/dev/null 2>&1 && iptables -w -n -L >/dev/null 2>&1; then
  warn "Docker's firewall rules are missing (flushed by a firewall restart such as csf -r); restarting Docker"
fi
bash "$DIR/deploy/docker-fw-check.sh" || die "Docker did not come back after a restart (systemctl status docker)"
# --force-recreate: a container left from a failed start (e.g. its network
# could not be set up) would otherwise be started again with a broken network
# ("getaddrinfo EAI_AGAIN db"). Data lives in named volumes and is kept.
compose_up() {
  if [ "$MODE" = caddy ]; then
    docker compose --profile caddy up -d --build --remove-orphans --force-recreate
  else
    # A Caddy container from an earlier attempt would fight Apache for port 80.
    docker compose --profile caddy rm -sf caddy >/dev/null 2>&1 || true
    docker compose up -d --build --remove-orphans --force-recreate
  fi
}
if ! compose_up; then
  # The rules can be flushed while the image builds: recreate them and retry once.
  warn "starting the containers failed; restarting Docker and trying again"
  systemctl restart docker
  for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
  compose_up
fi

# Recreate Docker's rules after every `csf -r` from now on.
CSFPOST=/usr/local/csf/bin/csfpost.sh
CSFTAG="# xPGuard portal: recreate Docker's firewall rules after csf -r"
if [ -f /etc/csf/csf.conf ]; then
  mkdir -p "$(dirname "$CSFPOST")"
  [ -s "$CSFPOST" ] || printf '#!/bin/sh\n' > "$CSFPOST"
  sed -i "\|$CSFTAG|d" "$CSFPOST"
  [ -z "$(tail -c1 "$CSFPOST")" ] || echo >> "$CSFPOST"
  echo "(sleep 5; bash $DIR/deploy/docker-fw-check.sh) >/dev/null 2>&1 & $CSFTAG" >> "$CSFPOST"
  chmod 700 "$CSFPOST"
  ok "CSF restarts recreate Docker's firewall rules (csfpost.sh)"
fi
# nftables.service (re)loads start with "flush ruleset", which removes
# Docker's chains too (a restart of nftables took the portal down once):
# restart Docker right after, so they are recreated.
if systemctl list-unit-files nftables.service 2>/dev/null | grep -q '^nftables.service'; then
  mkdir -p /etc/systemd/system/nftables.service.d
  cat > /etc/systemd/system/nftables.service.d/xpguard-docker.conf <<'EOF'
# xPGuard portal: recreate Docker's firewall chains after nftables flushed them.
[Service]
ExecStartPost=-/usr/bin/systemctl --no-block try-restart docker.service
ExecReload=-/usr/bin/systemctl --no-block try-restart docker.service
EOF
  systemctl daemon-reload
  ok "nftables restarts recreate Docker's firewall rules"
fi
remove_local_ai
docker image prune -f >/dev/null

step "Waiting for the portal"
healthy=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 3 "http://127.0.0.1:$PORTAL_PORT/api/health" >/dev/null 2>&1; then healthy=1; break; fi
  sleep 3
done
if [ "$healthy" = 0 ]; then
  # Recreate the stack's network and containers once (volumes are kept).
  warn "the portal did not answer; recreating its containers and network"
  docker compose logs --tail 20 portal || true
  docker compose down --remove-orphans
  bash "$DIR/deploy/docker-fw-check.sh" || true
  compose_up
  for _ in $(seq 1 60); do
    if curl -fsS --max-time 3 "http://127.0.0.1:$PORTAL_PORT/api/health" >/dev/null 2>&1; then healthy=1; break; fi
    sleep 3
  done
fi
[ "$healthy" = 1 ] || { docker compose logs --tail 60 portal; die "portal did not become healthy"; }
ok "portal answers on 127.0.0.1:$PORTAL_PORT"

# ------------------------------------------------------------------ cPanel
if [ "$MODE" = cpanel ]; then
  step "Configuring cPanel/Apache for $DOMAIN"

  # Apache proxy modules (EasyApache 4).
  for m in ea-apache24-mod_proxy ea-apache24-mod_proxy_http ea-apache24-mod_proxy_wstunnel ea-apache24-mod_headers; do
    rpm -q "$m" >/dev/null 2>&1 || dnf -y -q install "$m" >/dev/null 2>&1 || warn "could not install $m"
  done
  httpd -M 2>/dev/null | grep -q proxy_http_module || die "Apache mod_proxy_http is not available (install it in WHM > EasyApache 4)"
  ok "Apache proxy modules present"

  # The domain must belong to a cPanel account so Apache has a vhost and AutoSSL can issue a certificate.
  CPUSER=$(/usr/local/cpanel/scripts/whoowns "$DOMAIN" 2>/dev/null || true)
  if [ -z "$CPUSER" ]; then
    CPUSER=xmartgd
    i=1
    while [ -e "/var/cpanel/users/$CPUSER" ]; do CPUSER="xmartg$i"; i=$((i+1)); done
    PASS=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)
    out=$(whmapi1 --output=json createacct username="$CPUSER" domain="$DOMAIN" password="$PASS" contactemail="$EMAIL" 2>&1 || true)
    grep -q '"result":1' <<<"$out" || { echo "$out" | tail -20; die "could not create cPanel account for $DOMAIN"; }
    ok "created cPanel account '$CPUSER' for $DOMAIN (it only hosts the portal)"
  else
    ok "$DOMAIN belongs to cPanel account '$CPUSER'"
  fi

  UD=/etc/apache2/conf.d/userdata
  mkdir -p "$UD/std/2_4/$CPUSER/$DOMAIN" "$UD/ssl/2_4/$CPUSER/$DOMAIN"
  STD_CONF="$UD/std/2_4/$CPUSER/$DOMAIN/xmartguard.conf"
  SSL_CONF="$UD/ssl/2_4/$CPUSER/$DOMAIN/xmartguard.conf"
  # HTTP: keep /.well-known for AutoSSL validation, redirect everything else to HTTPS.
  cat >"$STD_CONF" <<'EOF'
# Managed by xPGuard setup-almalinux.sh
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{REQUEST_URI} !^/\.well-known/
  RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
</IfModule>
EOF
  # HTTPS: reverse proxy to the portal container, including the agent WebSocket.
  cat >"$SSL_CONF" <<EOF
# Managed by xPGuard setup-almalinux.sh
ProxyRequests Off
ProxyPreserveHost On
<IfModule mod_headers.c>
  RequestHeader set X-Forwarded-Proto "https"
</IfModule>
# The agents' WebSocket: a ws:// proxy rule, which LiteSpeed (reading this
# Apache config) and Apache's mod_proxy_wstunnel both follow. LiteSpeed
# ignores ProxyPass's upgrade=websocket, and the agents would stay offline.
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{HTTP:Upgrade} =websocket [NC]
  RewriteRule ^/?(api/agent/ws.*)$ ws://127.0.0.1:$PORTAL_PORT/\$1 [P,L]
</IfModule>
ProxyPass /.well-known !
ProxyPass / http://127.0.0.1:$PORTAL_PORT/ upgrade=websocket timeout=3600 keepalive=On
ProxyPassReverse / http://127.0.0.1:$PORTAL_PORT/
# The portal saves ModSecurity rules, license keys and rule URLs by design;
# a WAF on this vhost blocks those saves (and cPanel's error page then comes
# back from the portal as its home page). The portal has its own login,
# roles and CSRF checks.
<IfModule security2_module>
  SecRuleEngine Off
</IfModule>
EOF
  # The CAPTCHA page's domain: an alias of the portal's vhost, so the same
  # proxy include serves it and AutoSSL puts it on the same certificate.
  if [ "$CAPTCHA_DOMAIN" != none ]; then
    COWNER=$(/usr/local/cpanel/scripts/whoowns "$CAPTCHA_DOMAIN" 2>/dev/null || true)
    if [ -z "$COWNER" ]; then
      out=$(whmapi1 --output=json create_parked_domain_for_user domain="$CAPTCHA_DOMAIN" username="$CPUSER" web_vhost_domain="$DOMAIN" 2>&1 || true)
      if grep -q '"result":1' <<<"$out"; then
        ok "added $CAPTCHA_DOMAIN (CAPTCHA page) as an alias of $DOMAIN"
      else
        warn "could not add $CAPTCHA_DOMAIN as an alias of $DOMAIN: $(grep -o '"reason":"[^"]*"' <<<"$out" | head -1)"
      fi
    elif [ "$COWNER" = "$CPUSER" ]; then
      ok "$CAPTCHA_DOMAIN (CAPTCHA page) belongs to '$CPUSER'"
    else
      warn "$CAPTCHA_DOMAIN belongs to cPanel account '$COWNER': remove it there, or pass --captcha-domain none"
    fi
  fi
  /usr/local/cpanel/scripts/rebuildhttpdconf >/dev/null
  if ! httpd -t >/dev/null 2>&1; then
    httpd -t || true
    rm -f "$STD_CONF" "$SSL_CONF"
    /usr/local/cpanel/scripts/rebuildhttpdconf >/dev/null
    die "Apache rejected the proxy configuration (removed it again; your sites are unaffected)"
  fi
  /usr/local/cpanel/scripts/restartsrv_httpd >/dev/null 2>&1 || true
  ok "Apache proxies $DOMAIN -> 127.0.0.1:$PORTAL_PORT"

  step "Getting an SSL certificate with AutoSSL (can take a few minutes)"
  # cPanel SSL vhosts are bound to the server's public IP, not 127.0.0.1.
  CHECK_IP="${MYIP:-$DNSIP}"
  cert_ok() { curl -fsS --max-time 10 ${CHECK_IP:+--resolve "$DOMAIN:443:$CHECK_IP"} "https://$DOMAIN/api/health" >/dev/null 2>&1; }
  if ! cert_ok; then
    /usr/local/cpanel/bin/autossl_check --user="$CPUSER" >/dev/null 2>&1 || true
    for _ in $(seq 1 40); do
      cert_ok && break
      sleep 15
      # The SSL vhost (and our include) only exists once the certificate is installed.
      /usr/local/cpanel/scripts/rebuildhttpdconf >/dev/null 2>&1 && /usr/local/cpanel/scripts/restartsrv_httpd >/dev/null 2>&1 || true
    done
  fi
  if cert_ok; then
    ok "https://$DOMAIN is live with a valid certificate"
    if [ "$CAPTCHA_DOMAIN" != none ]; then
      CIP=$(getent ahostsv4 "$CAPTCHA_DOMAIN" | awk 'NR==1{print $1}' || true)
      captcha_ok() { curl -fsS --max-time 10 ${CHECK_IP:+--resolve "$CAPTCHA_DOMAIN:443:$CHECK_IP"} "https://$CAPTCHA_DOMAIN/" 2>/dev/null | grep -q 'xPGuard verification service'; }
      if ! captcha_ok; then
        /usr/local/cpanel/bin/autossl_check --user="$CPUSER" >/dev/null 2>&1 || true
        for _ in $(seq 1 20); do captcha_ok && break; sleep 15; done
      fi
      if captcha_ok; then
        ok "https://$CAPTCHA_DOMAIN (CAPTCHA page) is live"
      else
        warn "the CAPTCHA page https://$CAPTCHA_DOMAIN is not live yet (DNS: ${CIP:-not resolving}); add an A record for it pointing at ${MYIP:-this server} and run this script again"
      fi
    fi
  else
    warn "no valid certificate yet. In WHM open: SSL/TLS > Manage AutoSSL > Manage Users > run for '$CPUSER'"
    warn "then run this script again. The portal itself is running."
  fi
else
  step "Checking HTTPS"
  for _ in $(seq 1 20); do
    curl -fsS --max-time 10 "https://$DOMAIN/api/health" >/dev/null 2>&1 && { ok "https://$DOMAIN is live"; break; }
    sleep 6
  done
fi

ADMIN_PASSWORD=$(sed -n 's/^ADMIN_PASSWORD=//p' "$ENV")
echo ""
echo "============================================================"
echo " xPGuard portal:  https://$DOMAIN"
echo " Login email:         $(sed -n 's/^ADMIN_EMAIL=//p' "$ENV")"
echo " First password:      $ADMIN_PASSWORD"
echo "   (change it under Account after logging in)"
echo " AI scanner:          add free AI API keys (Gemini, Groq, OpenRouter) under AI Scanner"
[ "$CAPTCHA_DOMAIN" != none ] && echo " CAPTCHA page:        https://$CAPTCHA_DOMAIN  (add the Turnstile keys under Overview > CAPTCHA Page)"
echo " Update later:        curl -fsSL https://raw.githubusercontent.com/xmarthost/xmartguard/main/deploy/setup-almalinux.sh -o /root/setup.sh"
echo "                      bash /root/setup.sh --domain $DOMAIN --email $EMAIL"
echo " Logs:                cd $DIR/deploy && docker compose logs -f portal"
echo "============================================================"
