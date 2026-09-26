#!/usr/bin/env bash
# XMart Guard: free AI model for the AI scanner (Ollama).
#
# Two ways to use it:
#   1. On the portal server: deploy/setup-almalinux.sh calls this menu and runs
#      the model in Docker next to the portal (nothing is exposed publicly).
#   2. On a separate, bigger server (e.g. 64 GB RAM):
#        curl -fsSL https://raw.githubusercontent.com/xmarthost/xmartguard/main/deploy/setup-ai.sh -o setup-ai.sh
#        bash setup-ai.sh --portal-ip PORTAL_SERVER_IP [--model qwen2.5-coder:14b]
#      It installs Ollama, downloads the model and lets only the portal reach
#      port 11434. Then re-run the portal setup with --ai-url http://THIS_IP:11434.
#
# All models are free and open (downloaded from ollama.com). RAM figures are
# approximate for the default 4-bit versions with room for a 16k context.

# ---------------------------------------------------------------- catalog
# id | download | RAM needed | recommend (1 = candidate) | description
# On CPU-only servers speed matters: the recommendation is the best model
# marked 1 that fits; the others stay available.
XG_AI_MODELS=(
  "qwen2.5-coder:1.5b|1.0 GB|2 GB|1|Very fast, basic judgement (small VPS)"
  "qwen2.5-coder:3b|1.9 GB|4 GB|1|Fast, decent for obvious malware (8 GB RAM)"
  "qwen2.5-coder:7b|4.7 GB|6 GB|1|Good balance (16 GB RAM)"
  "deepseek-coder-v2:16b|8.9 GB|11 GB|0|Mixture-of-experts, fast for its size"
  "qwen2.5-coder:14b|9.0 GB|12 GB|1|Better reasoning (32 GB RAM)"
  "codestral:22b|12.6 GB|16 GB|0|Strong code model (Mistral), slower"
  "qwen3-coder:30b|19 GB|22 GB|1|Best speed/quality on CPU (48-64 GB RAM)"
  "qwen2.5-coder:32b|20 GB|24 GB|0|Highest quality, slow on CPU (64 GB RAM)"
)

xg_ram_gb() { [ -n "${XG_RAM_GB:-}" ] && { echo "$XG_RAM_GB"; return; }; awk '/MemTotal/{printf "%d", $2/1024/1024 + 0.5}' /proc/meminfo; }

# xg_ai_menu SHARE — prints the chosen model id (or "none") on stdout.
# SHARE is the share of RAM the model may use (percent): lower when the
# server also runs the portal or websites.
xg_ai_menu() {
  local share=${1:-60} ram allow best i id dl need rec desc mark choice
  ram=$(xg_ram_gb)
  allow=$(( ram * share / 100 ))
  best=""
  for i in "${!XG_AI_MODELS[@]}"; do
    IFS='|' read -r id dl need rec desc <<<"${XG_AI_MODELS[$i]}"
    if [ "$rec" = 1 ] && [ "${need%% *}" -le "$allow" ]; then best=$i; fi
  done
  {
    echo
    echo "  Free AI models for the XMart Guard AI scanner"
    echo "  This server has ${ram} GB RAM; up to ~${allow} GB can go to the model."
    echo
    printf "   %-3s %-24s %-10s %-9s %s\n" "#" "Model" "Download" "RAM" ""
    for i in "${!XG_AI_MODELS[@]}"; do
      IFS='|' read -r id dl need rec desc <<<"${XG_AI_MODELS[$i]}"
      mark=""
      [ "$i" = "$best" ] && mark="  <- recommended"
      [ "${need%% *}" -gt "$allow" ] && mark="  (needs more RAM)"
      printf "   %-3s %-24s %-10s %-9s %s%s\n" "$((i + 1))" "$id" "$dl" "$need" "$desc" "$mark"
    done
    echo "   0   No AI model (the free built-in model in every agent still works)"
    echo
  } >&2
  local def=0
  [ -n "$best" ] && def=$((best + 1))
  choice=""
  if { : </dev/tty; } 2>/dev/null; then
    read -r -p "  Choose a model [${def}]: " choice </dev/tty >&2 || choice=""
  fi
  choice=${choice:-$def}
  if [ "$choice" = 0 ]; then echo none; return; fi
  if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -gt "${#XG_AI_MODELS[@]}" ]; then echo none; return; fi
  IFS='|' read -r id dl need rec desc <<<"${XG_AI_MODELS[$((choice - 1))]}"
  if [ "${need%% *}" -gt "$allow" ]; then
    printf '  ! %s needs about %s RAM; this server may become slow.\n' "$id" "$need" >&2
  fi
  echo "$id"
}

xg_ai_known() {
  local m
  for m in "${XG_AI_MODELS[@]}"; do [ "${m%%|*}" = "$1" ] && return 0; done
  return 1
}

# Library mode: setup-almalinux.sh sources this file for the menu only.
[ "${XG_AI_LIB:-}" = 1 ] && return 0 2>/dev/null

# ---------------------------------------------------------------- standalone
set -Eeuo pipefail
PORTAL_IP=""; MODEL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --portal-ip) PORTAL_IP="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    *) echo "unknown option: $1"; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
[ -n "$PORTAL_IP" ] || { echo "usage: bash setup-ai.sh --portal-ip PORTAL_SERVER_IP [--model MODEL]"; exit 2; }

[ -n "$MODEL" ] || MODEL=$(xg_ai_menu 75)
[ "$MODEL" = none ] && { echo "no model chosen"; exit 0; }
xg_ai_known "$MODEL" || echo "  ! $MODEL is not in the tested list; trying anyway"

echo "==> Installing Ollama"
command -v ollama >/dev/null || curl -fsSL https://ollama.com/install.sh | sh
mkdir -p /etc/systemd/system/ollama.service.d
cat >/etc/systemd/system/ollama.service.d/xmartguard.conf <<CONF
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_KEEP_ALIVE=30m"
Environment="OLLAMA_NUM_PARALLEL=1"
CONF
systemctl daemon-reload
systemctl enable --now ollama >/dev/null
systemctl restart ollama
for _ in $(seq 1 30); do curl -fs http://127.0.0.1:11434/api/tags >/dev/null && break; sleep 1; done

echo "==> Downloading $MODEL (this can take a while)"
ollama pull "$MODEL"

echo "==> Allowing only the portal ($PORTAL_IP) to reach port 11434"
if systemctl is-active --quiet firewalld; then
  firewall-cmd -q --permanent --add-rich-rule="rule family=ipv4 source address=$PORTAL_IP port port=11434 protocol=tcp accept"
  firewall-cmd -q --reload
elif command -v csf >/dev/null; then
  grep -q "tcp|in|d=11434|s=$PORTAL_IP" /etc/csf/csf.allow 2>/dev/null || echo "tcp|in|d=11434|s=$PORTAL_IP # XMart Guard AI" >>/etc/csf/csf.allow
  csf -r >/dev/null
elif command -v iptables >/dev/null; then
  iptables -C INPUT -p tcp --dport 11434 -s "$PORTAL_IP" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 11434 -s "$PORTAL_IP" -j ACCEPT
  iptables -C INPUT -p tcp --dport 11434 -j DROP 2>/dev/null || iptables -A INPUT -p tcp --dport 11434 -j DROP
  echo "  ! iptables rules added; make them persistent with your distribution's tools"
fi

MYIP=$(curl -4 -fsS --max-time 10 https://api.ipify.org || hostname -I | awk '{print $1}')
echo
echo "============================================================"
echo " AI model ready: $MODEL on http://$MYIP:11434"
echo " On the portal server run the portal setup with:"
echo "   bash /root/setup.sh --domain YOUR_DOMAIN --email YOUR_EMAIL --ai-url http://$MYIP:11434 --ai-model $MODEL"
echo "============================================================"
