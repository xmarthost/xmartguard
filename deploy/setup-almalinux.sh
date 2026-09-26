#!/usr/bin/env bash
# One-shot XMart Guard PORTAL setup for AlmaLinux / Rocky / RHEL / CloudLinux 9.
#
#   bash setup-almalinux.sh --domain xmartguard.com --email you@example.com [--branch BRANCH] [--token GITHUB_TOKEN]
#        [--ai MODEL|none]                 free AI model on this server (asked interactively when omitted)
#        [--ai-url URL --ai-model MODEL]   use an AI server set up with deploy/setup-ai.sh
#
# Works on a plain VPS and on a server that already runs cPanel/WHM:
#   - plain VPS:  Caddy container serves ports 80/443 with automatic HTTPS.
#   - cPanel:     Apache keeps ports 80/443. The domain is attached to a cPanel
#                 account (created if needed), AutoSSL issues the certificate
#                 and an Apache include proxies the domain to the portal on
#                 127.0.0.1:18080. Other sites on the server are not touched.
# Safe to re-run: it updates the code and restarts the stack.
set -Eeuo pipefail

DOMAIN=""; EMAIL=""; BRANCH="main"; TOKEN="${GITHUB_TOKEN:-}"
AI=""; AI_URL=""; AI_MODEL=""
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
    --ai)     AI="$2"; shift 2 ;;
    --ai-url) AI_URL="$2"; shift 2 ;;
    --ai-model) AI_MODEL="$2"; shift 2 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32m✔\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mERROR: %s\033[0m\n' "$*"; exit 1; }
trap 'die "setup failed at line $LINENO"' ERR

[ "$(id -u)" -eq 0 ] || die "run as root"
[ -n "$DOMAIN" ] && [ -n "$EMAIL" ] || die "usage: bash setup-almalinux.sh --domain xmartguard.com --email you@example.com"
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

step "Checking DNS for $DOMAIN"
MYIP=$(curl -4 -fsS --max-time 10 https://api.ipify.org || true)
DNSIP=$(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}' || true)
echo "    this server: ${MYIP:-unknown}   $DOMAIN -> ${DNSIP:-not resolving}"
if [ -z "$DNSIP" ] || [ "$DNSIP" != "$MYIP" ]; then
  warn "$DOMAIN does not point at this server yet; HTTPS will not work until the A record is $MYIP."
fi

step "Installing packages and Docker"
dnf -y -q install git curl dnf-plugins-core openssl >/dev/null 2>&1 || dnf -y install git curl dnf-plugins-core openssl
if ! command -v docker >/dev/null; then
  dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo >/dev/null
  dnf -y -q install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
fi
systemctl enable --now docker >/dev/null
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
PORTAL_PORT=$(sed -n 's/^PORTAL_PORT=//p' "$ENV")

# ------------------------------------------------------------------ AI model
step "Free AI model for the AI scanner"
setenv() { sed -i "/^$1=/d" "$ENV"; [ -n "$2" ] && echo "$1=$2" >>"$ENV"; return 0; }
XG_AI_LIB=1 . "$DIR/deploy/setup-ai.sh"
CUR_MODEL=$(sed -n 's/^OLLAMA_MODEL=//p' "$ENV")
CUR_LOCAL=$(sed -n 's/^OLLAMA_LOCAL=//p' "$ENV")
if [ -n "$AI_URL" ]; then
  [ -n "$AI_MODEL" ] || die "--ai-url needs --ai-model (the model installed on that server)"
  setenv OLLAMA_URL "$AI_URL"; setenv OLLAMA_MODEL "$AI_MODEL"; setenv OLLAMA_LOCAL ""
  ok "using the AI server $AI_URL ($AI_MODEL)"
else
  if [ -z "$AI" ] && [ -n "$CUR_MODEL" ]; then
    AI=keep
  elif [ -z "$AI" ] && [ -r /dev/tty ] && [ -t 1 ]; then
    # The portal shares this server: leave most RAM to it (and to websites on cPanel).
    share=50; [ "$MODE" = cpanel ] && share=35
    AI=$(xg_ai_menu "$share")
  elif [ -z "$AI" ]; then
    AI=none
  fi
  case "$AI" in
    keep) ok "keeping ${CUR_MODEL} ($( [ "$CUR_LOCAL" = 1 ] && echo 'on this server' || sed -n 's/^OLLAMA_URL=//p' "$ENV"))" ;;
    none) setenv OLLAMA_URL ""; setenv OLLAMA_MODEL ""; setenv OLLAMA_LOCAL ""; ok "no AI model (agents use their built-in free model)" ;;
    *)
      xg_ai_known "$AI" || warn "$AI is not in the tested list; trying anyway"
      setenv OLLAMA_URL "http://ollama:11434"; setenv OLLAMA_MODEL "$AI"; setenv OLLAMA_LOCAL 1
      ok "will run $AI on this server" ;;
  esac
fi
AI_LOCAL=$(sed -n 's/^OLLAMA_LOCAL=//p' "$ENV")
AI_MODEL=$(sed -n 's/^OLLAMA_MODEL=//p' "$ENV")
PROFILES=""
[ "$AI_LOCAL" = 1 ] && PROFILES="--profile ai"

step "Building and starting the portal (first build takes several minutes)"
cd "$DIR/deploy"
if [ "$MODE" = caddy ]; then
  docker compose --profile caddy $PROFILES up -d --build --remove-orphans
else
  # A Caddy container from an earlier attempt would fight Apache for port 80.
  docker compose --profile caddy rm -sf caddy >/dev/null 2>&1 || true
  docker compose $PROFILES up -d --build --remove-orphans
fi
# A model container from an earlier setup is removed when AI is turned off or moved.
[ "$AI_LOCAL" = 1 ] || docker compose --profile ai rm -sf ollama >/dev/null 2>&1 || true
docker image prune -f >/dev/null

step "Waiting for the portal"
healthy=0
for _ in $(seq 1 60); do
  if curl -fsS --max-time 3 "http://127.0.0.1:$PORTAL_PORT/api/health" >/dev/null 2>&1; then healthy=1; break; fi
  sleep 3
done
[ "$healthy" = 1 ] || { docker compose logs --tail 60 portal; die "portal did not become healthy"; }
ok "portal answers on 127.0.0.1:$PORTAL_PORT"

if [ "$AI_LOCAL" = 1 ]; then
  step "Downloading the AI model $AI_MODEL (first time can take a while)"
  FREE_GB=$(df -BG --output=avail /var/lib/docker 2>/dev/null | tail -1 | tr -dc 0-9)
  if [ -n "$FREE_GB" ] && [ "$FREE_GB" -lt 25 ]; then warn "only ${FREE_GB} GB free disk for Docker; large models need up to 20 GB"; fi
  if docker compose exec -T ollama ollama pull "$AI_MODEL"; then
    ok "AI model $AI_MODEL ready (portal » server » Settings » Virus Scanner » AI scanner » XMart Guard AI server)"
  else
    warn "could not download $AI_MODEL; re-run this script to retry. Agents keep using their built-in model."
  fi
fi

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
# Managed by XMart Guard setup-almalinux.sh
<IfModule mod_rewrite.c>
  RewriteEngine On
  RewriteCond %{REQUEST_URI} !^/\.well-known/
  RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
</IfModule>
EOF
  # HTTPS: reverse proxy to the portal container, including the agent WebSocket.
  cat >"$SSL_CONF" <<EOF
# Managed by XMart Guard setup-almalinux.sh
ProxyRequests Off
ProxyPreserveHost On
<IfModule mod_headers.c>
  RequestHeader set X-Forwarded-Proto "https"
</IfModule>
ProxyPass /.well-known !
ProxyPass / http://127.0.0.1:$PORTAL_PORT/ upgrade=websocket timeout=3600 keepalive=On
ProxyPassReverse / http://127.0.0.1:$PORTAL_PORT/
EOF
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
echo " XMart Guard portal:  https://$DOMAIN"
echo " Login email:         $(sed -n 's/^ADMIN_EMAIL=//p' "$ENV")"
echo " First password:      $ADMIN_PASSWORD"
echo "   (change it under Account after logging in)"
[ -n "$AI_MODEL" ] && echo " AI scanner model:    $AI_MODEL"
echo " Update later:        curl -fsSL https://raw.githubusercontent.com/xmarthost/xmartguard/main/deploy/setup-almalinux.sh -o /root/setup.sh"
echo "                      bash /root/setup.sh --domain $DOMAIN --email $EMAIL"
echo " Logs:                cd $DIR/deploy && docker compose logs -f portal"
echo "============================================================"
