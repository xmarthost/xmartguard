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

### Command line: `xgcli`

Like cPanel's `cpgcli`, run as root on any server with the agent (`xgcli --help` lists everything):

```bash
xgcli status                                   # protection overview
xgcli scan --path /home/user/public_html       # scan and show progress
xgcli scan --list | --result ID [--export f.csv]
xgcli logs --status quarantined                # detections (log IDs)
xgcli view 123                                 # show a detected file, injected lines marked ">"
xgcli log-action --quarantine --user bob --from '-24 hours' --to now
xgcli log-action --trim --log-id 123           # remove only the code the AI located
xgcli ai-scan --provider portal --scope all    # free AI APIs, check every new file
xgcli trim --enable --max 20
xgcli fw --deny-country CN,RU | --port tcp-in --add 2083 | --ipdb enable
xgcli ip --temp-ban 203.0.113.9 --expiry 2h --reason 'scanner'
xgcli ip --allow 10.0.0.1 --reason 'office' | --check 10.0.0.1
xgcli whitelist --user --add alice | --file --add /home/a/public_html/cache
xgcli waf --disable webshell | --whitelist --add 7700012
xgcli config --export settings.json            # and --import FILE|URL on another server
```

Also: `scanner`, `dailyscan`, `weeklyscan`, `watch`, `blacklist`, `file-action`, `cleanup`, `lfd`, `bot-check`, `account-suspend`, `rootkit`, `process-monitor`, `cron-monitor`, `osm`, `ip-reputation`, `dbscan`, `notification`, `cms`, `upload-scanner`, `cloud`. Low level: `xmartguard-agent call ACTION '{json}'`, `xmartguard-agent check PATH` (offline scan).

## What it protects (0.7.3)

| Module | What it does |
|---|---|
| Malware scanner | Accounts on any partition (`/home`, `/home2`, `/home3`, …, from `/etc/passwd` and cPanel), addon-domain document roots, `/tmp`, `/var/tmp` and `/dev/shm`. Realtime (inotify on every account's home, extracted archives and moved folders caught instantly, worker pool with overflow catch-up; the AI check runs in the background), quick/full/path with **live progress** (files, %, ETA, current file), daily and weekly scans; own heuristic analyzer with **behaviour families** (silent loaders, XOR/char decoders, function tables, admin-login backdoors, cloaking, `.user.ini` loaders, HTML disguised as images — 91% of real malware caught without any hash) + known-bad hash database + fleet-learned hashes + **Linux Malware Detect** signatures + **web shell YARA rules** (signature-base) + ClamAV + own YARA rules; **official WordPress core files (every release and beta since 5.8) and WordPress.org plugin files are never flagged**; infected core files are **replaced with the official file** of the site's version; quarantine/restore/disable/delete/trim/false positive; view detected files from the logs; insecure symlink detection. See [docs/SIGNATURES.md](docs/SIGNATURES.md) |
| AI scanner | **Free AI APIs** (Gemini, Groq, OpenRouter, Cerebras, Mistral, GitHub Models, NVIDIA, Hugging Face, Cloudflare, any OpenAI-compatible) configured once in the portal for all servers, many keys per provider with automatic failover; batched, compact requests; **shared knowledge base** (a file judged on one server is known on all); **fleet training** of every server's built-in model; checks detections only or every new file; **Trim** removes only injected code and keeps the site live. Offline default: built-in model |
| WAF | Own ModSecurity rules for Apache and **LiteSpeed** (cPanel+LiteSpeed automatic incl. restart and LiteSpeed log format; standalone LiteSpeed/Enhance/CyberPanel via one WebAdmin WAF rule set, see the portal's Knowledge Base; tested on ModSecurity 2.9): uploads scanned by the malware engine, web shell and exploit-probe blocking (PHPUnit eval-stdin, Laravel Ignition, leaked credentials), PHP-upload blocking, sensitive files, WordPress hardening incl. user enumeration, bad/SEO/AI/custom bots, protected login URLs, whitelisted domains; **on/off per rule**, config test with automatic rollback |
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
| Portal | cPGuard-style collapsible sidebar with group flyouts, server dashboard with **protection status** (realtime scanner, firewall, IPDB, WAF: running / not running alerts), Knowledge Base with setup guides and third-party attributions, Firewall Logs with flags/CSV, Mass Operations, roles, audit log |

## IPDB — shared attacker blocklist

Every server reports the attackers it bans automatically (brute force, DoS). The portal lists an address once it has been reported by `IPDB_MIN_REPORTERS` servers (default 2) or `IPDB_MIN_REPORTS` times (default 3) within `IPDB_WINDOW_DAYS` (7); entries expire `IPDB_TTL_DAYS` (30) after the last report. Public feeds (`IPDB_FEEDS`, default Spamhaus DROP) and operator-managed manual entries and whitelist are merged in. Every agent drops the list in its own ipset/nftables set, counts hits per address and reports them back for the **IPDB** page: world map of attack origins, live monitor, daily chart and top attackers. Addresses of your own servers and private ranges are never listed. Country data: [DB-IP Lite](https://db-ip.com) (CC BY 4.0), downloaded by the portal into `DATA_DIR`.

## Deploy the portal

On AlmaLinux/Rocky/RHEL/CloudLinux 9 (plain VPS or a cPanel server), with the domain's A record pointing at it:

```bash
curl -fsSL https://raw.githubusercontent.com/xmarthost/xmartguard/main/deploy/setup-almalinux.sh -o /root/setup.sh
bash /root/setup.sh --domain xmartguard.com --email you@example.com
```

The script installs Docker, builds the portal, sets up HTTPS and prints the first admin password. Re-run the same two lines to update.

### AI scanner (free AI APIs)

Nothing runs on the portal server: open **AI Scanner** in the portal and add free API keys. Every linked server uses them through the portal (requests are signed with each agent's key).

| Provider | Free key | Free limits (approx.) |
|---|---|---|
| Google Gemini | [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) | 10–15 requests/min, daily cap per model |
| Groq | [console.groq.com/keys](https://console.groq.com/keys) | 30 requests/min, 1,000/day per model |
| OpenRouter | [openrouter.ai/keys](https://openrouter.ai/keys) | `:free` models, 20/min, 50/day (1,000/day after a $10 top-up) |
| Mistral, Cerebras, GitHub Models, NVIDIA NIM, Hugging Face, Cloudflare Workers AI | see the portal | small free tiers |

- Add as many keys as you like (e.g. 5–7 Gemini keys, then Groq and OpenRouter). Lower priority numbers are tried first; keys with the same priority share the load. A key that hits its limit, fails or is rejected rests (as long as the provider's `Retry-After` says, an hour for daily quotas) and the next key answers.
- **Fetch models** lists the models of a key (OpenRouter: only free ones by default).
- Tokens stay low: files any server already had judged are answered from the shared knowledge base; up to 6 files share one request and one copy of the instructions; big files are reduced to their start, end and the lines around risky calls; long encoded strings are shortened; the fixed instructions come first so providers that cache prompts reuse them.
- Per server (Settings » Virus Scanner » AI scanner): **XMart Guard AI** and which files go to the AI — detections only, or every new/changed code file (with an hourly cap) so the scanner learns from them.
- **Learn from all servers**: files any server's AI found malicious (≥90%) become hash detections everywhere within 10 minutes, and the portal retrains a small update of the built-in model from the AI's verdicts that every agent applies. Correct a verdict under AI Scanner » Shared knowledge and all servers follow.
- **Trim** (Settings » Virus Scanner): when the AI marks code injected into a legitimate file, only those lines are removed; the file must pass `php -l` and a rescan, and the original stays in quarantine (Restore puts it back).

Upgrading from 0.5: re-running the setup script removes the local AI model (Ollama container, its downloaded models and a native Ollama installed by the old `setup-ai.sh`). Servers set to Ollama or Claude switch to XMart Guard AI automatically. On a separate AI server made with the old `setup-ai.sh`: `systemctl disable --now ollama && rm -rf /usr/local/bin/ollama /usr/local/lib/ollama /usr/share/ollama /etc/systemd/system/ollama.service*`.

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
