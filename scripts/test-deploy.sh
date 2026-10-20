#!/usr/bin/env bash
# shellcheck disable=SC2034  # variables are used inside eval-ed check strings
# Checks of installer/ and deploy/ scripts that need no root, no network and
# no portal: each one runs a piece of a script against stub commands in a
# temporary folder and changes nothing on this machine.
#
#   scripts/test-deploy.sh
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin"

pass=0; fail=0
check() { if eval "$2"; then echo "  PASS  $1"; pass=$((pass+1)); else echo "  FAIL  $1"; fail=$((fail+1)); fi; }

echo "== selftest.sh shows the firewall chain the agent uses =="
cat >"$WORK/bin/iptables" <<'EOF'
#!/bin/sh
# Stub: XG_CHAIN is the chain the (fake) agent created.
case "$*" in
  "-w -S $XG_CHAIN") echo "-N $XG_CHAIN" ;;
  "-w -S INPUT") echo "-P INPUT ACCEPT"; echo "-A INPUT -j $XG_CHAIN" ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$WORK/bin/iptables"
sed -n '/^# Agents since the xPGuard name/,/^echo "--- INPUT jump"/p' "$ROOT/installer/selftest.sh" >"$WORK/fw.sh"
out=$(XG_CHAIN=XPGUARD PATH="$WORK/bin:$PATH" bash "$WORK/fw.sh" 2>&1)
check "current agent: XPGUARD chain"  'grep -q -- "--- XPGUARD chain" <<<"$out" && grep -q -- "-A INPUT -j XPGUARD" <<<"$out" && ! grep -q "no jump" <<<"$out"'
out=$(XG_CHAIN=XMARTGUARD PATH="$WORK/bin:$PATH" bash "$WORK/fw.sh" 2>&1)
check "old agent: XMARTGUARD chain"   'grep -q -- "--- XMARTGUARD chain" <<<"$out" && grep -q -- "-A INPUT -j XMARTGUARD" <<<"$out"'

echo "== install.sh: https only, http and --insecure only for localhost =="
# Never given a token: a run that passes the address checks stops at the
# token check (or, without root, at the root check) before changing anything.
inst() { bash "$ROOT/installer/install.sh" "$@" 2>&1 || true; }
URLERR="must start with https|only allowed for a portal on this machine|invalid --server"
for u in http://203.0.113.10 http://portal.example.com:8080/ "http://127.0.0.1.example.com" "http://evil.example#@127.0.0.1" "http://127.0.0.1@evil.example" ftp://portal.example.com; do
  out=$(inst --server "$u")
  check "refused: $u" 'grep -Eq "$URLERR" <<<"$out"'
done
out=$(inst --server https://portal.example.com --insecure)
check "refused: --insecure for a remote portal" 'grep -q "only allowed for a portal on this machine" <<<"$out"'
for a in "--server https://portal.example.com" "--server http://localhost:8080" "--server http://127.0.0.1:8080/" "--server http://[::1]:8080" "--server https://127.0.0.1 --insecure"; do
  # shellcheck disable=SC2086  # split into options on purpose
  out=$(inst $a)
  check "accepted: $a" '! grep -Eq "$URLERR" <<<"$out" && grep -Eq "missing --token|please run as root" <<<"$out"'
done

echo "== install.sh rotates the agent log; uninstall.sh may remove that file =="
sed -n '/^  cat >"\$LOGROTATE" <<EOF/,/^EOF/p' "$ROOT/installer/install.sh" >"$WORK/lr.sh"
LOGROTATE=$WORK/logrotate.conf LOG_DIR=/opt/xpguard/logs bash "$WORK/lr.sh"
check "rotates agent.log by size"  'grep -q "^/opt/xpguard/logs/agent.log " "$WORK/logrotate.conf" && grep -Eq "^ +size " "$WORK/logrotate.conf" && grep -Eq "^ +copytruncate" "$WORK/logrotate.conf" && grep -Eq "^ +rotate " "$WORK/logrotate.conf"'
check "install.sh records it"      'grep -qF "record file \"\$LOGROTATE\"" "$ROOT/installer/install.sh"'
if command -v logrotate >/dev/null 2>&1; then
  check "logrotate accepts it"     'logrotate -d "$WORK/logrotate.conf" >/dev/null 2>&1'
fi
sed -n '/^safe_path() {/,/^}/p' "$ROOT/installer/uninstall.sh" >"$WORK/safe.sh"
# shellcheck source=/dev/null
. "$WORK/safe.sh"
check "uninstall may remove it"    'safe_path /etc/logrotate.d/xpguard-agent && ! safe_path /etc/logrotate.d/httpd'

SETUP=$ROOT/deploy/setup-almalinux.sh
fn() { sed -n "/^$1() {/,/^}/p" "$SETUP"; }
ok() { echo "ok: $*"; }

echo "== setup-almalinux.sh keeps the GitHub token out of URLs and command lines =="
cat >"$WORK/bin/git" <<'EOF'
#!/bin/sh
# Stub: record the arguments and the last git config entry in the environment.
n=$((${GIT_CONFIG_COUNT:-0} - 1))
{ echo "args: $*"; echo "count: ${GIT_CONFIG_COUNT:-0}"; eval "echo \"key: \${GIT_CONFIG_KEY_$n:-}\""; eval "echo \"value: \${GIT_CONFIG_VALUE_$n:-}\""; } >"$XG_GIT_LOG"
EOF
chmod +x "$WORK/bin/git"
fn git_auth >"$WORK/git_auth.sh"
# shellcheck source=/dev/null
. "$WORK/git_auth.sh"
# One entry already in the environment, as on hosts that set git options so.
TOKEN=tok-0123456789 XG_GIT_LOG=$WORK/git.log PATH="$WORK/bin:$PATH" GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.askPass GIT_CONFIG_VALUE_0='' git_auth clone -q --branch main https://github.com/owner/repo.git "$WORK/clone"
check "token not in git's arguments" '! grep -q tok-0123456789 "$WORK/git.log" && grep -q "args: clone -q --branch main https://github.com/owner/repo.git" "$WORK/git.log"'
check "token sent as a header"       'grep -qx "count: 2" "$WORK/git.log" && grep -qxF "key: http.https://github.com/.extraHeader" "$WORK/git.log" && [ "$(sed -n "s/^value: Authorization: Basic //p" "$WORK/git.log" | base64 -d)" = x-access-token:tok-0123456789 ]'
TOKEN="" XG_GIT_LOG=$WORK/git.log PATH="$WORK/bin:$PATH" GIT_CONFIG_COUNT=0 git_auth fetch -q origin main
check "no header without a token"    'grep -qx "count: 0" "$WORK/git.log"'
# shellcheck disable=SC2016  # the literal text older versions used
pat='x-access-token:${TOKEN}@'
check "no token in a remote URL"     '! grep -qF "$pat" "$SETUP"'

echo "== setup-almalinux.sh prints secrets only when it made them =="
fn secret_line >"$WORK/secret_line.sh"
# shellcheck source=/dev/null
. "$WORK/secret_line.sh"
ENV=$WORK/env
out=$(SHOW_SECRETS=0 secret_line "Billing secret: " s3cr3t-value 0)
check "kept secret hidden"           '! grep -q s3cr3t-value <<<"$out" && grep -q -- "--show-secrets" <<<"$out"'
out=$(SHOW_SECRETS=0 secret_line "Billing secret: " s3cr3t-value 1)
check "new secret shown once"        'grep -q "Billing secret: s3cr3t-value" <<<"$out"'
out=$(SHOW_SECRETS=1 secret_line "Billing secret: " s3cr3t-value 0)
check "--show-secrets shows it"      'grep -q "Billing secret: s3cr3t-value" <<<"$out"'
check "banner uses secret_line"      '! grep -Eq "^echo .*(BILLING_SECRET=|ADMIN_PASSWORD\")" "$SETUP" && [ "$(grep -c "^ *secret_line " "$SETUP")" -eq 2 ]'

echo "== setup-almalinux.sh drops the first password once the owner exists =="
cat >"$WORK/bin/docker" <<'EOF'
#!/bin/sh
# Stub: "docker compose exec ... psql" answers with XG_USERS.
[ -n "${XG_USERS:-}" ] || exit 1
echo "$XG_USERS"
EOF
chmod +x "$WORK/bin/docker"
fn forget_first_password >"$WORK/forget.sh"
# shellcheck source=/dev/null
. "$WORK/forget.sh"
for n in 0 "" 1; do
  printf 'DOMAIN=portal.example.com\nADMIN_PASSWORD=first-pass-123\nBILLING_SECRET=x\n' >"$ENV"
  XG_USERS=$n PATH="$WORK/bin:$PATH" forget_first_password >/dev/null
  if [ "$n" = 1 ]; then
    check "removed when an account exists" 'grep -qx "ADMIN_PASSWORD=" "$ENV" && grep -qx "DOMAIN=portal.example.com" "$ENV"'
  else
    check "kept with no accounts / no db (${n:-down})" 'grep -qx "ADMIN_PASSWORD=first-pass-123" "$ENV"'
  fi
done
check "not on the run that made .env" 'grep -qF "[ \"\$NEW_ENV\" = 1 ] || forget_first_password" "$SETUP"'

echo "== .gitignore keeps secret and runtime files out of the repository =="
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  for f in .env.backup deploy/.env.local logs/agent.log server/tls.pem server/tls.key etc/identity.key etc/agent.json data.db agent/x.sqlite bench/sample.php quarantine/sample.php; do
    check "ignored: $f" 'git -C "$ROOT" check-ignore -q --no-index "$f"'
  done
  for f in deploy/.env.example agent/internal/quarantine/store.go server/src/routes/logs.ts; do
    check "not ignored: $f" '! git -C "$ROOT" check-ignore -q --no-index "$f"'
  done
fi

echo "== CI actions are pinned by commit =="
unpinned=$(grep -hE '^[[:space:]-]*uses:' "$ROOT"/.github/workflows/*.yml | grep -vE 'uses: [^@ ]+@[0-9a-f]{40}( |$)' || true)
check "every uses: names a commit SHA" '[ -z "$unpinned" ]'

echo ""
echo "deploy script tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
