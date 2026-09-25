#!/usr/bin/env bash
# XMart Guard agent installer.
#
#   curl -fsSL __XG_PORTAL_URL__/install.sh | bash -s -- --token XG-XXXX-XXXX-...
#
# Options:
#   --token TOKEN     one-time enrollment token from the portal (required)
#   --server URL      portal URL (default: __XG_PORTAL_URL__)
#   --insecure        accept a self-signed portal certificate (testing only)
#   --force           re-install even if the agent is already installed
#
# Every file and change this script makes is recorded in
# /var/lib/xmartguard/manifest so uninstall.sh can remove exactly those.
set -Eeuo pipefail

PORTAL_URL="__XG_PORTAL_URL__"
TOKEN=""
INSECURE=0
FORCE=0

BIN=/usr/local/bin/xmartguard-agent
CONF_DIR=/etc/xmartguard
STATE_DIR=/var/lib/xmartguard
LOG_DIR=/var/log/xmartguard
UNIT=/etc/systemd/system/xmartguard-agent.service
MANIFEST=$STATE_DIR/manifest
INSTALL_LOG=$LOG_DIR/install.log

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_ylw=$'\033[33m'; c_bld=$'\033[1m'; c_off=$'\033[0m'
[ -t 1 ] || { c_red=""; c_grn=""; c_ylw=""; c_bld=""; c_off=""; }

say()  { printf '%s\n' "$*"; [ -w "$INSTALL_LOG" ] && printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$INSTALL_LOG" || true; }
ok()   { say "  ${c_grn}✔${c_off} $*"; }
warn() { say "  ${c_ylw}!${c_off} $*"; }
die()  { say "  ${c_red}✘ $*${c_off}"; exit 1; }
trap 'die "installation failed at line $LINENO (see $INSTALL_LOG)"' ERR

while [ $# -gt 0 ]; do
  case "$1" in
    --token)    TOKEN="${2:-}"; shift 2 ;;
    --token=*)  TOKEN="${1#*=}"; shift ;;
    --server)   PORTAL_URL="${2:-}"; shift 2 ;;
    --server=*) PORTAL_URL="${1#*=}"; shift ;;
    --insecure) INSECURE=1; shift ;;
    --force)    FORCE=1; shift ;;
    -h|--help)  sed -n '2,15p' "$0" 2>/dev/null || true; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done
PORTAL_URL="${PORTAL_URL%/}"

say ""
say "${c_bld}XMart Guard installer${c_off}"
say ""

# ---------------------------------------------------------------- preflight
[ "$(id -u)" -eq 0 ] || die "please run as root"
[ -n "$TOKEN" ] || die "missing --token (copy the install command from the portal: Add Server)"
case "$PORTAL_URL" in https://*|http://*) ;; *) die "invalid --server URL: $PORTAL_URL" ;; esac
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || die "systemd is required"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported CPU architecture: $(uname -m)" ;;
esac

OS_NAME="unknown"
if [ -r /etc/os-release ]; then . /etc/os-release; OS_NAME="${PRETTY_NAME:-$ID}"; fi

if [ -f "$MANIFEST" ] && [ "$FORCE" -ne 1 ]; then
  die "XMart Guard is already installed. Uninstall first, or pass --force to re-install."
fi

mkdir -p "$LOG_DIR"; chmod 0750 "$LOG_DIR"
: >>"$INSTALL_LOG"
ok "OS: $OS_NAME ($ARCH)"

CURL=(curl -fsSL --retry 3 --connect-timeout 15 --max-time 300)
[ "$INSECURE" -eq 1 ] && CURL+=(-k)

# ---------------------------------------------------------------- download
# Not /tmp: hardened servers (cPanel "securetmp") mount it noexec.
TMP=$(mktemp -d -p /var/lib xmartguard-install.XXXXXX)
trap 'rm -rf "$TMP"' EXIT
FILE="xmartguard-agent-linux-$ARCH"
"${CURL[@]}" -o "$TMP/$FILE" "$PORTAL_URL/downloads/$FILE" || die "could not download the agent from $PORTAL_URL"
"${CURL[@]}" -o "$TMP/$FILE.sha256" "$PORTAL_URL/downloads/$FILE.sha256" || die "could not download the agent checksum"
EXPECTED=$(awk '{print $1}' "$TMP/$FILE.sha256")
ACTUAL=$(sha256sum "$TMP/$FILE" | awk '{print $1}')
[ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch for the agent binary"
chmod 0755 "$TMP/$FILE"
"$TMP/$FILE" version >/dev/null || die "downloaded agent does not run on this system"
ok "Agent downloaded and verified ($("$TMP/$FILE" version))"

# ---------------------------------------------------------------- manifest
# Manifest line format:  <kind> <path>
#   file   - created by us, delete on uninstall
#   dir    - created by us, remove if empty on uninstall (rm -rf for our own dirs)
#   unit   - systemd unit we installed
mkdir -p "$STATE_DIR"; chmod 0700 "$STATE_DIR"
if [ ! -f "$MANIFEST" ]; then
  {
    echo "# xmartguard install manifest v1"
    echo "# installed_at $(date -u +%FT%TZ)"
    echo "dir $STATE_DIR"
    echo "dir $LOG_DIR"
  } >"$MANIFEST"
  chmod 0600 "$MANIFEST"
fi
record() { grep -qxF "$1 $2" "$MANIFEST" 2>/dev/null || echo "$1 $2" >>"$MANIFEST"; }

# Stop an existing agent when re-installing.
if systemctl is-active --quiet xmartguard-agent 2>/dev/null; then
  systemctl stop xmartguard-agent || true
fi

# ---------------------------------------------------------------- install files
[ -d "$CONF_DIR" ] || { mkdir -p "$CONF_DIR"; }
chmod 0700 "$CONF_DIR"
record dir "$CONF_DIR"

install -m 0755 "$TMP/$FILE" "$BIN"
record file "$BIN"
ln -sfn "$BIN" /usr/local/bin/xmartguard
record file /usr/local/bin/xmartguard
ok "Installed $BIN"

# ---------------------------------------------------------------- enroll
ENROLL_ARGS=(enroll --server "$PORTAL_URL" --token "$TOKEN")
[ "$INSECURE" -eq 1 ] && ENROLL_ARGS+=(--insecure)
[ "$FORCE" -eq 1 ] && ENROLL_ARGS+=(--force)
if ! OUT=$("$BIN" "${ENROLL_ARGS[@]}" 2>&1); then
  say "$OUT"
  die "enrollment failed. Create a fresh token in the portal (Add Server) and run the command again."
fi
record file "$CONF_DIR/agent.json"
record file "$CONF_DIR/identity.key"
ok "$OUT"

# ---------------------------------------------------------------- systemd
cat >"$UNIT" <<EOF
[Unit]
Description=XMart Guard security agent
Documentation=$PORTAL_URL
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN run
Restart=on-failure
RestartSec=10
StandardOutput=append:$LOG_DIR/agent.log
StandardError=append:$LOG_DIR/agent.log
Nice=5
LimitNOFILE=65536
NoNewPrivileges=yes
ProtectSystem=full
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"
record unit "$UNIT"
record file "$LOG_DIR/agent.log"
systemctl daemon-reload
systemctl enable --now xmartguard-agent >/dev/null 2>&1
sleep 3
systemctl is-active --quiet xmartguard-agent || die "the agent service did not start (journalctl -u xmartguard-agent)"
ok "Service xmartguard-agent is running"

# Keep a local copy of the uninstaller so it works without network access.
"${CURL[@]}" -o "$STATE_DIR/uninstall.sh" "$PORTAL_URL/uninstall.sh" 2>/dev/null && chmod 0700 "$STATE_DIR/uninstall.sh" || true

say ""
say "${c_grn}${c_bld}XMart Guard installed successfully.${c_off}"
say "This server will appear in your portal within a minute: $PORTAL_URL"
say "Uninstall: bash $STATE_DIR/uninstall.sh   (or: curl -fsSL $PORTAL_URL/uninstall.sh | bash)"
say ""
