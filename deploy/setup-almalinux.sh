#!/usr/bin/env bash
# One-shot XMart Guard PORTAL setup for a fresh AlmaLinux / Rocky / RHEL 9 VPS.
#
#   bash setup-almalinux.sh --domain xmartguard.com --email you@example.com [--branch BRANCH] [--token GITHUB_TOKEN]
#
# Installs Docker, opens ports 80/443, clones the repo to /opt/xmartguard,
# generates passwords, and starts PostgreSQL + portal + Caddy (auto HTTPS).
# Safe to re-run: it updates the code and restarts the stack.
set -Eeuo pipefail

DOMAIN=""; EMAIL=""; BRANCH="main"; TOKEN="${GITHUB_TOKEN:-}"
REPO="github.com/xmarthost/xmartguard.git"
DIR=/opt/xmartguard

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --email)  EMAIL="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --token)  TOKEN="$2"; shift 2 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*"; exit 1; }
trap 'die "setup failed at line $LINENO"' ERR

[ "$(id -u)" -eq 0 ] || die "run as root"
[ -n "$DOMAIN" ] && [ -n "$EMAIL" ] || die "usage: bash setup-almalinux.sh --domain xmartguard.com --email you@example.com"
. /etc/os-release
case "${ID}${ID_LIKE:-}" in *rhel*|*almalinux*|*rocky*|*centos*) ;; *) die "this script is for AlmaLinux/Rocky/RHEL 9";; esac

step "Checking DNS for $DOMAIN"
MYIP=$(curl -4 -fsS --max-time 10 https://api.ipify.org || true)
DNSIP=$(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}' || true)
echo "this server: ${MYIP:-unknown}   $DOMAIN -> ${DNSIP:-not resolving}"
if [ -z "$DNSIP" ] || [ "$DNSIP" != "$MYIP" ]; then
  echo "WARNING: $DOMAIN does not point at this server yet. HTTPS certificates will fail until the A record is $MYIP."
fi

step "Installing packages and Docker"
dnf -y -q install git curl dnf-plugins-core openssl >/dev/null
if ! command -v docker >/dev/null; then
  dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo >/dev/null
  dnf -y -q install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
fi
systemctl enable --now docker >/dev/null
docker --version

# Building the image needs ~2 GB RAM; add swap on small VPSes.
MEM_MB=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
if [ "$MEM_MB" -lt 3000 ] && ! swapon --show | grep -q .; then
  step "Adding 2 GB swap (RAM is ${MEM_MB} MB)"
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile >/dev/null && swapon /swapfile
  grep -q '^/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >>/etc/fstab
fi

step "Opening firewall ports 80 and 443"
if systemctl is-active --quiet firewalld; then
  firewall-cmd -q --permanent --add-service=http --add-service=https && firewall-cmd -q --reload
  echo "firewalld updated"
else
  echo "firewalld not running; make sure ports 80/443 are open at your provider"
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
git -C "$DIR" log --oneline -1

step "Writing configuration"
ENV="$DIR/deploy/.env"
NEW_ADMIN_PASSWORD=""
if [ ! -f "$ENV" ]; then
  NEW_ADMIN_PASSWORD=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)
  cat >"$ENV" <<EOF
DOMAIN=$DOMAIN
POSTGRES_PASSWORD=$(openssl rand -hex 24)
ADMIN_EMAIL=$EMAIL
ADMIN_PASSWORD=$NEW_ADMIN_PASSWORD
EOF
  chmod 600 "$ENV"
  echo "created $ENV"
else
  sed -i "s/^DOMAIN=.*/DOMAIN=$DOMAIN/" "$ENV"
  echo "kept existing $ENV"
fi

step "Building and starting the portal (first build takes a few minutes)"
cd "$DIR/deploy"
docker compose up -d --build
docker image prune -f >/dev/null

step "Waiting for the portal"
for _ in $(seq 1 60); do
  if docker compose exec -T portal node -e "fetch('http://127.0.0.1:8080/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null; then
    ok=1; break
  fi
  sleep 3
done
[ "${ok:-0}" = 1 ] || { docker compose logs --tail 50 portal; die "portal did not become healthy"; }
docker compose ps

echo ""
echo "============================================================"
echo " XMart Guard portal is running:  https://$DOMAIN"
if [ -n "$NEW_ADMIN_PASSWORD" ]; then
  echo " Login email:     $EMAIL"
  echo " Login password:  $NEW_ADMIN_PASSWORD"
  echo " (change it under Account after logging in; it is also in $ENV)"
fi
echo " Update later:    bash $DIR/deploy/setup-almalinux.sh --domain $DOMAIN --email $EMAIL --branch $BRANCH"
echo " Logs:            cd $DIR/deploy && docker compose logs -f portal"
echo "============================================================"
