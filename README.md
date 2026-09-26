# XMart Guard

Server security platform for hosting servers: a cloud portal (`xmartguard.com`) plus a lightweight agent installed on each server with one command.

```
Portal (React UI + Node.js API + PostgreSQL)  <== outbound WebSocket (TLS, Ed25519-signed auth) ==  xmartguard-agent (Go, systemd)
```

The agent connects **out** to the portal, so managed servers don't need any inbound port or IP whitelist.

## Repository layout

| Path | What |
|---|---|
| `agent/` | Go agent: enrollment, identity key, inventory/metrics collection, portal session, commands |
| `server/` | Portal API (Fastify + PostgreSQL): auth, users/roles, enrollment tokens, agent WebSocket hub, metrics, audit log, installer/binary downloads |
| `web/` | Portal UI (React + Tailwind + Recharts) |
| `installer/` | One-line `install.sh` / `uninstall.sh` and the real-server `selftest.sh` (served by the portal with its URL baked in) |
| `deploy/` | Docker Compose stack for the portal (PostgreSQL + portal + Caddy auto-HTTPS) |
| `scripts/` | `build-agent.sh`, `test-installer.sh` |
| `docs/` | `PLAN.md` (roadmap), `TESTING.md` (real-server test procedure) |

## Install / uninstall on a server

The portal's **Add Server** page generates a one-time token (valid 24 h, single use) and the command:

```bash
curl -fsSL https://xmartguard.com/install.sh | bash -s -- --token XG-XXXX-XXXX-XXXX-XXXX-XXXX
```

Uninstall (removes exactly what the installer recorded in `/opt/xmartguard/manifest`, including the cPanel/WHM plugins, and prints a residue report):

```bash
curl -fsSL https://xmartguard.com/uninstall.sh | bash
# or offline:  bash /opt/xmartguard/uninstall.sh [--dry-run] [--keep-logs]
```

Files on a managed server (same `/etc` + `/opt` layout as other hosting security suites):

| Path | Purpose |
|---|---|
| `/etc/xmartguard/agent.json` (0600) | portal URL and server ID |
| `/etc/xmartguard/identity.key` (0600) | Ed25519 private key; never leaves the server |
| `/etc/xmartguard/settings.json` (0600) | security policy (scanner, firewall, IPDB, notifications) |
| `/opt/xmartguard/bin/xmartguard-agent` | agent binary (linked as `/usr/local/bin/xmartguard-agent` and `xmartguard`) |
| `/opt/xmartguard/data/` (0700) | local database, signature updates, IPDB list, `quarantine/` |
| `/opt/xmartguard/logs/` | `agent.log`, `install.log` |
| `/opt/xmartguard/manifest`, `uninstall.sh` | install manifest and local uninstaller |
| `/run/xmartguard/agent.sock` | local control socket (plugins, `xmartguard call`) |
| `/etc/systemd/system/xmartguard-agent.service` | systemd unit |

Servers installed with 0.2.x (`/var/lib/xmartguard`) are migrated automatically when the agent updates.

### cPanel / WHM plugins

On cPanel servers the agent installs two plugins (and refreshes them on every update):

- **WHM » Plugins » XMart Guard** (root): overview, virus scans (quick/full/path), detected files with quarantine/restore/disable/delete/ignore, firewall block/allow/check, IPDB status.
- **cPanel » Security » XMart Guard** (every account): scan your own website and quarantine, restore or delete your own detected files.

The plugins have no logic of their own: they talk to the agent's local socket, which identifies the caller by its Unix uid (kernel `SO_PEERCRED`). A cPanel account can only see and act on files inside its own home directory. To disable the plugins: `touch /etc/xmartguard/no-panel-plugin && xmartguard-agent panel uninstall`.

Command line (root): `xmartguard-agent call overview`, `xmartguard-agent call fw.add '{"kind":"deny","addr":"203.0.113.9"}'`, `xmartguard-agent check /home/user/public_html` (offline scan).

## What it protects (0.5.1)

| Module | What it does |
|---|---|
| Malware scanner | Realtime (inotify), quick/full/path, daily and weekly scans; own heuristic analyzer + known-bad hash database + ClamAV + optional YARA rules (`/etc/xmartguard/yara/*.yar`); quarantine/restore/disable/delete; insecure symlink detection; auto clean of infected WordPress core files from the official release |
| AI scanner | Second opinion on suspicious files. Default: **built-in model, free and local** (logistic regression over code features, trained on real quarantine data; retrain with `xmartguard-agent ai-train`). Free LLM on the portal (installer menu picks an Ollama model for the RAM), own Ollama, or Claude (own Anthropic API key) |
| WAF | Own ModSecurity rules for Apache/LiteSpeed: uploads scanned by the malware engine, web shell protection, PHP-upload blocking, sensitive files, WordPress hardening, bad/SEO/AI/custom bots, protected login URLs, whitelisted domains; per-rule disable, config test with automatic rollback |
| Brute force | SSH, cPanel/WHM/Webmail, Dovecot, Postfix, Exim, FTP, Apache denials and CMS logins; per-rule exclusion; addresses the WAF keeps blocking are banned ("N WAF blocked") |
| Firewall | iptables+ipset (default) or nftables: allow/deny/temp ban/temp allow/ignore lists, ignored/allowed/blocked countries, DDNS allowlist, port filter (TCP/UDP in/out), DoS, self-healing; **CAPTCHA page for banned visitors** (built-in image challenge, or Turnstile/reCAPTCHA); live log of blocked connections |
| IPDB | Shared attacker blocklist across all servers with live monitor, hourly/live charts and world map; IPDB log switch and IPDB CAPTCHA |
| CMS | WordPress/Joomla/OpenCart discovery, outdated core/plugins/themes, core checksum verification, **known vulnerabilities (WPVulnerability, CVE + CVSS)**, automatic updates of vulnerable plugins/themes, blacklisted plugins, wp-cron override |
| DB scanner | Read-only scan of WordPress databases for injected scripts, hidden iframes and PHP; signature whitelist |
| Process & cron monitor | Miners, reverse shells and programs run from temporary/hidden folders (alert or kill); malicious user crontabs; weekly rkhunter rootkit check |
| Outgoing spam | Exim per-sender limits per minute/hour, spam-subject checks, hold/suspend outgoing mail (cPanel) |
| Reputation | Server IPs on DNS blocklists; hosted domains on Spamhaus DBL/SURBL/URIBL and optionally Google Safe Browsing |
| Automatic suspension | Suspend cPanel accounts after repeated malware detections or a blacklisted domain |
| Notifications | Email (+ additional address, custom From), Slack, Telegram, daily report; user notifications (infected files, suspension, CMS patches, outdated CMS digest) |
| Portal | cPGuard-style server dashboard, Firewall Logs with flags/CSV, Mass Operations, roles, audit log |

## IPDB — shared attacker blocklist

Every server reports the attackers it bans automatically (brute force, DoS). The portal lists an address once it has been reported by `IPDB_MIN_REPORTERS` servers (default 2) or `IPDB_MIN_REPORTS` times (default 3) within `IPDB_WINDOW_DAYS` (7); entries expire `IPDB_TTL_DAYS` (30) after the last report. Public feeds (`IPDB_FEEDS`, default Spamhaus DROP) and operator-managed manual entries and whitelist are merged in. Every agent drops the list in its own ipset/nftables set, counts hits per address and reports them back for the **IPDB** page: world map of attack origins, live monitor, daily chart and top attackers. Addresses of your own servers and private ranges are never listed. Country data: [DB-IP Lite](https://db-ip.com) (CC BY 4.0), downloaded by the portal into `DATA_DIR`.

## Deploy the portal

On AlmaLinux/Rocky/RHEL/CloudLinux 9 (plain VPS or a cPanel server), with the domain's A record pointing at it:

```bash
curl -fsSL https://raw.githubusercontent.com/xmarthost/xmartguard/main/deploy/setup-almalinux.sh -o /root/setup.sh
bash /root/setup.sh --domain xmartguard.com --email you@example.com
```

The script installs Docker, builds the portal, sets up HTTPS and prints the first admin password. Re-run the same two lines to update.

### Free AI model (optional)

During setup a menu lists free AI models (Ollama) with the RAM each needs and recommends one for the server's RAM (the portal leaves most RAM to itself and to websites). The model runs in Docker next to the portal and is never exposed; agents send suspicious files to the portal, signed with their key, and pick **XMart Guard AI server** as AI provider (Settings » Virus Scanner, or Mass Operations » "Use the portal AI model").

| Model | Download | RAM | Recommended for |
|---|---|---|---|
| qwen2.5-coder:1.5b | 1.0 GB | 2 GB | small VPS |
| qwen2.5-coder:3b | 1.9 GB | 4 GB | 8 GB RAM |
| qwen2.5-coder:7b | 4.7 GB | 6 GB | 16 GB RAM |
| deepseek-coder-v2:16b | 8.9 GB | 11 GB | option |
| qwen2.5-coder:14b | 9.0 GB | 12 GB | 32 GB RAM |
| codestral:22b | 12.6 GB | 16 GB | option (slower) |
| qwen3-coder:30b | 19 GB | 22 GB | 48–64 GB RAM (best on CPU) |
| qwen2.5-coder:32b | 20 GB | 24 GB | option (slow on CPU) |

Options: `--ai MODEL` (no menu), `--ai none`, or run the model on a separate bigger server:

```bash
# on the AI server (e.g. 64 GB RAM)
curl -fsSL https://raw.githubusercontent.com/xmarthost/xmartguard/main/deploy/setup-ai.sh -o setup-ai.sh
bash setup-ai.sh --portal-ip PORTAL_SERVER_IP
# then on the portal server
bash /root/setup.sh --domain xmartguard.com --email you@example.com --ai-url http://AI_SERVER_IP:11434 --ai-model qwen3-coder:30b
```

Without any of this, every agent still uses its built-in free model.

## Development

Requirements: Go 1.24+, Node 22+, PostgreSQL 16.

```bash
scripts/build-agent.sh                       # agent binaries -> dist/downloads
cd server && npm ci && ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=change-me-now npm run dev
cd web && npm ci && npm run dev              # http://localhost:5173 (proxies /api to :8080)
```

Tests:

```bash
(cd agent && go test ./...)
(cd server && npm test)          # needs postgres://xg:xg@localhost:5432/xmartguard_test (TEST_DATABASE_URL)
PORTAL=http://localhost:8080 ADMIN_EMAIL=... ADMIN_PASSWORD=... scripts/test-installer.sh   # destructive; disposable machine only
```

CI (`.github/workflows/ci.yml`) runs all of the above, including a real-systemd install/uninstall.

## Security model (M1)

- One-time, 24-hour enrollment tokens; only their SHA-256 is stored.
- Each agent generates an Ed25519 key locally; the portal stores only the public key. Every WebSocket session is authenticated by signing a fresh server nonce; unenroll requests are signed and time-bounded.
- Removing a server in the portal revokes it: the agent is disconnected and stops itself.
- Portal sessions are httpOnly cookies (hashed at rest), roles `owner > admin > operator > viewer`, tenant isolation on every query, JSON-only + same-origin checks on mutations, rate-limited login and enrollment, audit log of security events.
- Installer verifies the SHA-256 of the downloaded agent and refuses to run without systemd or as non-root.
