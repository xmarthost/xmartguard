#!/usr/bin/env bash
# xPGuard agent installer.
#
#   curl -fsSL __XG_PORTAL_URL__/install.sh | bash -s -- --token XG-XXXX-XXXX-...
#
# Options:
#   --token TOKEN     one-time enrollment token from the portal (required)
#   --server URL      portal URL (default: __XG_PORTAL_URL__)
#   --insecure        accept a self-signed portal certificate (testing only)
#   --force           re-install even if the agent is already installed
#
# Layout:
#   /etc/xpguard          configuration, identity key, security policy
#   /opt/xpguard/bin      agent binary (symlinked into /usr/local/bin)
#   /opt/xpguard/data     local database, signatures, IPDB list, quarantine
#   /opt/xpguard/logs     agent and install logs
# Every file and change this script makes is recorded in
# /opt/xpguard/manifest so uninstall.sh can remove exactly those.
set -Eeuo pipefail

PORTAL_URL="__XG_PORTAL_URL__"
TOKEN=""
INSECURE=0
FORCE=0

HOME_DIR=/opt/xpguard
BIN=$HOME_DIR/bin/xpguard-agent
CONF_DIR=/etc/xpguard
STATE_DIR=$HOME_DIR
LOG_DIR=$HOME_DIR/logs
# Directories of versions before the xPGuard name (moved by migrate-layout).
OLD_HOME=/opt/xmartguard
OLD_CONF=/etc/xmartguard
LEGACY_MANIFEST=/var/lib/xmartguard/manifest
UNIT=/etc/systemd/system/xpguard-agent.service
OLD_UNIT=/etc/systemd/system/xmartguard-agent.service
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
say "${c_bld}xPGuard installer${c_off}"
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

if [ -d "$OLD_HOME/.git" ]; then
  die "$OLD_HOME holds the xPGuard portal code from an older portal setup. Re-run deploy/setup-almalinux.sh on this server first (it moves the portal to /opt/xmartguard-portal)."
fi

if { [ -f "$MANIFEST" ] || [ -f "$OLD_HOME/manifest" ] || [ -f "$LEGACY_MANIFEST" ]; } && [ "$FORCE" -ne 1 ]; then
  die "xPGuard is already installed. Uninstall first, or pass --force to re-install."
fi

# /opt/xpguard must be traversable: cPanel accounts run the plugin binary.
mkdir -p "$HOME_DIR/bin" "$LOG_DIR"; chmod 0755 "$HOME_DIR" "$HOME_DIR/bin"; chmod 0750 "$LOG_DIR"
: >>"$INSTALL_LOG"
ok "OS: $OS_NAME ($ARCH)"

CURL=(curl -fsSL --retry 3 --connect-timeout 15 --max-time 300)
[ "$INSECURE" -eq 1 ] && CURL+=(-k)

# ---------------------------------------------------------------- dependencies
# ipset is used by the (default) iptables firewall provider.
if ! command -v ipset >/dev/null 2>&1; then
  if command -v dnf >/dev/null 2>&1; then dnf -y -q install ipset >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then yum -y -q install ipset >/dev/null 2>&1 || true
  elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q ipset >/dev/null 2>&1 || true
  fi
  command -v ipset >/dev/null 2>&1 && ok "Installed ipset" || warn "ipset could not be installed; the firewall will need it"
fi

# conntrack clears the CAPTCHA redirect of an unblocked visitor's open connections.
if ! command -v conntrack >/dev/null 2>&1; then
  if command -v dnf >/dev/null 2>&1; then dnf -y -q install conntrack-tools >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then yum -y -q install conntrack-tools >/dev/null 2>&1 || true
  elif command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y -q conntrack >/dev/null 2>&1 || true
  fi
fi

# ---------------------------------------------------------------- download
# Not /tmp: hardened servers (cPanel "securetmp") mount it noexec.
TMP=$(mktemp -d -p "$HOME_DIR" .install.XXXXXX)
trap 'rm -rf "$TMP"' EXIT
FILE="xpguard-agent-linux-$ARCH"
"${CURL[@]}" -o "$TMP/$FILE" "$PORTAL_URL/downloads/$FILE" || die "could not download the agent from $PORTAL_URL"
"${CURL[@]}" -o "$TMP/$FILE.sha256" "$PORTAL_URL/downloads/$FILE.sha256" || die "could not download the agent checksum"
EXPECTED=$(awk '{print $1}' "$TMP/$FILE.sha256")
ACTUAL=$(sha256sum "$TMP/$FILE" | awk '{print $1}')
[ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch for the agent binary"
chmod 0755 "$TMP/$FILE"
"$TMP/$FILE" version >/dev/null || die "downloaded agent does not run on this system"
ok "Agent downloaded and verified ($("$TMP/$FILE" version))"

# Stop an existing agent when re-installing (current and older service name).
for u in xpguard-agent xmartguard-agent; do
  if systemctl is-active --quiet "$u" 2>/dev/null; then systemctl stop "$u" || true; fi
done
# Re-install over a version from before the xPGuard name: move its
# configuration and data to /etc/xpguard and /opt/xpguard.
if { [ -d "$OLD_CONF" ] && [ ! -L "$OLD_CONF" ]; } || { [ -d "$OLD_HOME" ] && [ ! -L "$OLD_HOME" ]; }; then
  if OUT=$("$TMP/$FILE" migrate-layout 2>&1); then
    ok "Moved $OLD_CONF and $OLD_HOME to $CONF_DIR and $HOME_DIR"
  else
    say "$OUT"
    die "could not move $OLD_CONF / $OLD_HOME to the new locations"
  fi
fi

# ---------------------------------------------------------------- manifest
# Manifest line format:  <kind> <path>
#   file   - created by us, delete on uninstall
#   dir    - created by us, remove if empty on uninstall (rm -rf for our own dirs)
#   unit   - systemd unit we installed
if [ ! -f "$MANIFEST" ]; then
  {
    echo "# xpguard install manifest v1"
    echo "# installed_at $(date -u +%FT%TZ)"
    echo "dir $STATE_DIR"
    echo "dir $LOG_DIR"
  } >"$MANIFEST"
  chmod 0600 "$MANIFEST"
fi
record() { grep -qxF "$1 $2" "$MANIFEST" 2>/dev/null || echo "$1 $2" >>"$MANIFEST"; }

# ---------------------------------------------------------------- install files
[ -d "$CONF_DIR" ] || { mkdir -p "$CONF_DIR"; }
chmod 0700 "$CONF_DIR"
record dir "$CONF_DIR"

mkdir -p "$HOME_DIR/bin"
install -m 0755 "$TMP/$FILE" "$BIN"
record file "$BIN"
record dir "$HOME_DIR/bin"
record dir "$HOME_DIR/data"
ln -sfn "$BIN" /usr/local/bin/xpguard-agent
ln -sfn "$BIN" /usr/local/bin/xgcli
record file /usr/local/bin/xpguard-agent
record file /usr/local/bin/xgcli
# Links of versions before the xPGuard name.
for l in /usr/local/bin/xmartguard-agent /usr/local/bin/xmartguard; do
  if [ -L "$l" ]; then rm -f "$l"; fi
done
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

# ---------------------------------------------------------------- kernel / CSF
# The realtime scanner watches every account's home with inotify; keep the
# limit across reboots.
SYSCTL=/etc/sysctl.d/xpguard.conf
if [ ! -f "$SYSCTL" ]; then
  echo "fs.inotify.max_user_watches = 10000000" >"$SYSCTL"
  record file "$SYSCTL"
fi
sysctl -p "$SYSCTL" >/dev/null 2>&1 || true
# CSF/LFD: do not alert on the agent's own process.
if [ -f /etc/csf/csf.pignore ] && ! grep -qxF "exe:$BIN" /etc/csf/csf.pignore; then
  echo "exe:$BIN" >>/etc/csf/csf.pignore
  record line "/etc/csf/csf.pignore exe:$BIN"
  command -v lfd >/dev/null 2>&1 && (service lfd restart >/dev/null 2>&1 || true)
  ok "CSF/LFD ignores the xPGuard agent process"
fi

# ---------------------------------------------------------------- systemd
# The agent manages the firewall, quarantines files anywhere under /home and
# updates itself, so it runs as root without filesystem sandboxing.
cat >"$UNIT" <<EOF
[Unit]
Description=xPGuard security agent
Documentation=$PORTAL_URL
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN run
Restart=on-failure
RestartSec=5
StandardOutput=append:$LOG_DIR/agent.log
StandardError=append:$LOG_DIR/agent.log
Nice=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"
record unit "$UNIT"
record file "$LOG_DIR/agent.log"
# The service of older versions is replaced by xpguard-agent.
if [ -f "$OLD_UNIT" ]; then
  systemctl disable xmartguard-agent >/dev/null 2>&1 || true
  rm -f "$OLD_UNIT"
fi
# The old program path is not used any more.
if [ -f /etc/csf/csf.pignore ] && grep -qxF "exe:$OLD_HOME/bin/xmartguard-agent" /etc/csf/csf.pignore; then
  grep -vxF "exe:$OLD_HOME/bin/xmartguard-agent" /etc/csf/csf.pignore >/etc/csf/csf.pignore.xg && cat /etc/csf/csf.pignore.xg >/etc/csf/csf.pignore && rm -f /etc/csf/csf.pignore.xg
fi
systemctl daemon-reload
systemctl enable --now xpguard-agent >/dev/null 2>&1
sleep 3
systemctl is-active --quiet xpguard-agent || die "the agent service did not start (journalctl -u xpguard-agent)"
ok "Service xpguard-agent is running"

# ---------------------------------------------------------------- panel plugins
if [ -f /usr/local/cpanel/version ]; then
  if OUT=$("$BIN" panel install 2>&1); then
    ok "cPanel/WHM plugins installed (WHM » Plugins » xPGuard, cPanel » Security » xPGuard)"
  else
    warn "cPanel plugin could not be registered: $OUT"
  fi
  record panel cpanel
fi

# Keep a local copy of the uninstaller so it works without network access.
"${CURL[@]}" -o "$STATE_DIR/uninstall.sh" "$PORTAL_URL/uninstall.sh" 2>/dev/null && chmod 0700 "$STATE_DIR/uninstall.sh" || true

say ""
say "${c_grn}${c_bld}xPGuard installed successfully.${c_off}"
say "This server will appear in your portal within a minute: $PORTAL_URL"
say "Uninstall: bash $STATE_DIR/uninstall.sh   (or: curl -fsSL $PORTAL_URL/uninstall.sh | bash)"
say ""
