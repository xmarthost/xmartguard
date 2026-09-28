# xPGuard — complete project report (A to Z)

Status: version **0.9.3** (September 2026). This report is written so that a
developer or another AI assistant can continue the work without any other
context. Read it top to bottom once; later use the tables as a map.

> **Khulasa (Roman Urdu):** xPGuard aik server security tool hai, cPGuard jaisa,
> jo hosting servers (zyada tar cPanel) ko malware, hacking attacks, brute force aur
> spam se bachata hai. Aik portal (app.xpguard.org) hai jahan se sab servers manage
> hote hain, aur har server par aik chhota Go agent chalta hai. Neeche har hissa,
> har file ki jagah, kaam karne ka tareeqa, test/release ka tareeqa aur baqi kaam
> tafseel se likha hai.

---

## 1. What the product is

- **Goal:** a security suite for web-hosting servers comparable to cPGuard
  (OpsShield): malware scanner with quarantine, web application firewall
  (ModSecurity), firewall and brute-force protection, shared IP blocklist,
  WordPress/CMS protection, outgoing-spam monitor, reputation checks,
  cPanel/WHM plugins, and a central web portal for many servers.
- **Owner / users:** a hosting company. The owner communicates in
  **Roman Urdu**; replies to the owner are given in Roman Urdu, with progress
  shown as a task list, and each release ends with update instructions and
  screenshots.
- **Hard rules (legal/ethical):**
  - cPGuard was studied only for behaviour (its install script, file layout,
    readable configs, SQLite schemas). Its application code is ionCube-encoded and
    was **never decoded**. **No cPGuard code, signatures, rules or IPDB feed may be
    copied** into this repository.
  - Commercial rule/signature sets (Malware.Expert WAF rules and PHP signatures)
    are **not** copied. Customers use **their own license** through the provided
    hooks (WHM vendor URL, `SecRemoteRules`, ClamAV-format subscription URL).
  - WAF rules stay defensive. Never print malware contents or write exploits.
  - Everything here is xPGuard's own code, written from public
    documentation and observed behaviour.

## 2. Architecture

```
 Browser ──HTTPS──> Portal (server/ + web/)                 PostgreSQL
                    Fastify API + React SPA  <──────────────> (accounts, servers,
                          ^                                   findings mirror, IPDB,
                          | outbound WebSocket (TLS),         AI keys, WAF rule sets…)
                          | Ed25519-signed session
                    xpguard-agent (Go, systemd, root)  — one per hosting server
                          |  local Unix socket /run/xmartguard/agent.sock
                          +── WHM plugin (root)  +── cPanel plugin (each account)
```

- The agent always connects **out** to the portal (no inbound port, unlike
  cPGuard's port 9098). The portal sends commands over that WebSocket
  (`hub.command`), the agent answers. Agents also call signed HTTP endpoints
  (`/api/agent/...`, body signed with the server's Ed25519 key, verified by
  `signedPayload` in `server/src/agent-sign.ts`).
- Scheduled work runs **inside** the agent (Go goroutines), not cron. systemd
  restarts the agent if it stops.
- WHM/cPanel plugins have no logic: they relay JSON to the agent's local socket;
  the agent identifies the caller by Unix uid (`SO_PEERCRED`) and limits a cPanel
  user to files/sites inside their own home.

## 3. Repository map

| Path | Content |
|---|---|
| `agent/` | Go agent (module `github.com/xmarthost/xmartguard/agent`) |
| `agent/cmd/xmartguard-agent/` | `main.go` (commands: `enroll`, `run`, `status`, `check`, `cleanup`, `panel …`, `panel-cgi`, `panel-api`, `call`, `cli`/`xgcli`), `cli.go` (xgcli, cpgcli-like) |
| `agent/internal/…` | agent packages (table below) |
| `server/` | Portal API: Fastify + TypeScript + PostgreSQL (`server/src`) and tests (`server/test`, vitest) |
| `web/` | Portal UI: React + Vite + Tailwind v4 + Recharts (`web/src`) |
| `installer/` | `install.sh`, `uninstall.sh` (manifest-based), `selftest.sh`; served by the portal with its URL baked in |
| `deploy/` | `setup-almalinux.sh` (one-command portal install/update on AlmaLinux/Rocky/RHEL/CloudLinux 9, also on a cPanel server), `docker-compose.yml`, `Caddyfile` |
| `scripts/` | `build-agent.sh` (agent binaries → `dist/downloads`), `test-installer.sh` (destructive e2e) |
| `docs/` | this report, `PLAN.md`, `TESTING.md`, `SIGNATURES.md`, `WAF-RULESETS.md`, `AI-TRAINING.md`, `CPGUARD-PARITY.md` |
| `VERSION`, `agent/internal/version/version.go` | version (bump both on every release: `0.9.3` and `"0.9.3-dev"`) |

### 3.1 Agent packages (`agent/internal/`)

| Package | Responsibility |
|---|---|
| `core` | Builds every module (`New`), starts loops (`Start`), the **command table** `Handlers()` (portal commands), local-socket server (`panel.go`: root + cPanel-user handlers), settings apply logic, dashboards, reports (`report.go`), host-firewall trust loop (`hosttrust.go`), ClamAV loader loop (`clamav.go`) |
| `scanner` | Malware scanner: scans (quick/full/path/daily/weekly), realtime inotify, `CheckFile` pipeline, heuristics (`analyze.go`, `heuristics.go`, `families.go`, `rules.go`), hash DB, LMD/YARA feed patterns, zip scanning (`archive.go`), ClamAV hook (`clam.go`), phishing checks (`phishing.go`), quarantine/restore/disable/delete, **Record** (stores findings; skips AI-cleared content), trim of injected code |
| `clamdb` | Own engine for **ClamAV-format** databases (`.cvd/.cld/.hdb/.hsb/.ndb/.ldb/.fp/.ign2`) matched in-process: hex sigs with wildcards/gaps/alternatives, logical sigs with counts, PCRE subsigs (RE2), subscription download (`fetch.go`) |
| `ai` | AI scanner: jobs, verdict cache/knowledge base (`ai_verdicts`), cleared-content list (`IsCleared`), built-in model and portal AI provider |
| `ml` | Small built-in ML model (fleet-trained) |
| `waf` | ModSecurity integration: detection of web server/panel (`install.go`, hooks cPanel via `modsec2.user.conf`), own rules (`rules.go`, ids 7700000–7709999), rule sets (OWASP CRS, WHM vendors, `SecRemoteRules`, custom; `rulesets.go`), self-test (`selftest.go`), log/audit-log reading and events DB (`waf.go`, `auditlog.go`), proxy IP check and trusted-service lists |
| `firewall` | iptables+ipset or nftables backend, allow/deny/temp lists, countries, DDNS, port filter, DoS, CAPTCHA redirect, IPDB list, brute-force jails (`bruteforce.go`), connection log, **CSF compatibility** (`csf.go`) |
| `hostfw` | Allows the portal's IPs in CSF (allow+ignore), firewalld, UFW, APF, cPHulk, Imunify360; state file; removes only its own entries |
| `trusted` | Trusted services (Googlebot, Bingbot, Applebot, DuckDuckBot, UptimeRobot, Pingdom, StatusCake, Better Stack, Cloudflare, Stripe, PayPal, Jetpack, Softaculous, cPanel): official lists refreshed daily, built-in/DNS fallback |
| `captcha` | Built-in CAPTCHA web server (and Turnstile/reCAPTCHA) for banned visitors |
| `cms` | WordPress/Joomla/OpenCart discovery, versions, vulnerabilities (WPVulnerability), auto-update, blacklisted plugins, wp-cron, **DB scanner** (`dbscan.go`) |
| `wpcore` | Official WordPress core / plugin checksums, core file repair |
| `mail` | Outgoing spam monitor (Exim, `osm.go`), **Exim RBL definitions** for WHM (`eximrbl.go`) |
| `reputation` | Server IP DNSBL checks, hosted domain reputation (DBL/SURBL/URIBL, Safe Browsing) |
| `monitor` | Process monitor (miners, reverse shells), cron monitor, rkhunter |
| `panel` | WHM/cPanel plugin installation, CGI/PHP bridge, page `ui.html` (WHM mode + cPanel-user mode) |
| `local` | Local Unix socket server/client, uid-based access |
| `client` | Portal WebSocket session |
| `settings` | `settings.json` model (`Settings` struct), defaults, `normalize`, `validate`, `Patch` |
| `store` | SQLite database (`/opt/xmartguard/data`), schema and column migrations, KV |
| `identity`, `config` | Ed25519 identity, agent config/paths |
| `notify` | Email/Slack/Telegram notifications, daily report |
| `sysinfo`, `logtail`, `updater`, `protocol`, `version` | inventory/metrics, log tailing, self-update, wire types, version |

### 3.2 Portal server (`server/src/`)

| File | Responsibility |
|---|---|
| `index.ts`, `app.ts`, `config.ts`, `db.ts`, `migrations.ts` | start-up, route registration, config, pool, inline SQL migrations (`00x_…`) |
| `auth.ts`, `security.ts` | sessions (httpOnly cookie), roles `owner > admin > operator > viewer`, CSRF (JSON + same-origin), rate limits, audit |
| `agents/hub.ts`, `agents/release.ts` | WebSocket hub for agents, commands, agent release/update |
| `agent-sign.ts` | verification of signed agent requests |
| `routes/agent-cmd.ts` | **allowlist `ACTIONS`** of agent commands the UI may call, with minimum role and timeout. A new agent command is unusable from the portal until listed here |
| `routes/servers.ts`, `users.ts`, `auth.ts`, `downloads.ts`, `agent.ts` | servers, users, login, installer/binary downloads, agent enrolment/endpoints |
| `routes/ipdb.ts`, `ipdb/` | shared attacker blocklist (IPDB), geo data |
| `routes/ai.ts`, `ai/` | AI provider pool with failover (Gemini, Groq, OpenRouter, …), knowledge base, fleet training |
| `routes/waf-rulesets.ts`, `waf/rulesets.ts` | WAF Rule Sets for all servers, OWASP CRS download service |
| `routes/mcp.ts` | AI connector (MCP) for Claude and other clients |
| `routes/mass.ts` | mass operations across servers |
| `routes/appearance.ts` | portal themes |
| `signatures/`, `wpcore/` | public signature feeds (LMD, YARA), WordPress core files |

### 3.3 Portal UI (`web/src/`)

`pages/`: `Overview`, `ServerList`, `ServerDashboard` (+ `components/AttackOverview.tsx`),
`Scanner` (manual scans, scanner logs, **scan report**), `CMS` (CMS threats, DB scanner),
`WAF` (WAF logs, bot attacks), `WafRuleSets`, `Firewall` (rules, countries, ports,
trusted services, server firewalls, CAPTCHA), `IPDB`, `ServerIPDB`, `Mail`,
`Monitoring`, `SecurityMonitor`, `Settings` (per-server settings: Virus Scanner incl.
ClamAV, RBL & IP Reputation incl. Exim RBLs, IPDB, WAF & Bruteforce, WordPress/CMS,
Automatic Suspension, Additional, Outgoing Spam, Notifications, About), `AIScanner`,
`AIConnector`, `AppearancePage`, `MassOperations`, `KnowledgeBase`, `Admin`, `Login`,
`AddServer`. Shared: `components/controls.tsx` (`useAgent`, `agentCall`,
`ListEditor`, `Toggle`, `SettingRow`, …), `components/ui.tsx`, `components/Layout.tsx`,
`theme.ts` (9 themes + custom).

## 4. On a managed server

| Path | Purpose |
|---|---|
| `/opt/xpguard/bin/xpguard-agent` | agent program under `xpguard-agent.service` (links `/usr/local/bin/xpguard-agent`, `xgcli`, and `/opt/xmartguard/bin/xmartguard-agent` for older scripts). Installs from before 0.10.1 are switched over by the agent itself (transient systemd job, rolls back to the old unit if the new one is not active after 20 s). |
| `/etc/xmartguard/agent.json`, `identity.key`, `settings.json` | config, private key, security policy |
| `/etc/xmartguard/waf/` | generated ModSecurity rules and lists (`rules.conf`, bot lists, `trusted-ips.txt`, `blocked-ips.txt`, `proxy-ranges.txt`, CRS) |
| `/opt/xmartguard/data/` | SQLite DB, quarantine, signature caches, `clamav/` subscriptions, `trusted-services.json`, `host-trust.json` |
| `/run/xmartguard/agent.sock` | local control socket (plugins, `xpguard-agent call ACTION '{json}'`) |
| `/etc/systemd/system/xpguard-agent.service` | service |
| Hooks written | `modsec2.user.conf` Include (cPanel), `/etc/sysctl.d/xmartguard.conf` (inotify), `csf.pignore`, `csfpost.sh` line, `/var/cpanel/rbl_info/*.yaml` (+ `exim.conf.localopts`), host firewall entries; all removed by `uninstall.sh` → `xpguard-agent cleanup` |

## 5. Features (A to Z)

- **AI scanner:** second opinion on detections (or all new files), free AI APIs
  configured once in the portal (key pool with failover), shared knowledge base,
  fleet training of the built-in model, **Trim** (removes only injected code).
  A clean verdict ≥ 90% restores the file (**Restored by AI**) and the content is
  never flagged again until it changes — enforced centrally in `scanner.Record`
  for every file type (0.8.1).
- **AI connector (MCP):** Claude/other AI clients read dashboards, findings, logs;
  read-write connectors can act (audited). In Claude choose Authentication "No sign-in".
- **Appearance:** 9 ready themes (light/dark) + custom colours, saved for every
  user; persists across sessions (fixed in 0.9.3).
- **Auto suspension:** suspend cPanel accounts after repeated detections or a
  blacklisted domain.
- **Brute force:** SSH, cPanel/WHM/Webmail, mail, FTP, Apache, CMS logins;
  WAF-driven bans; CAPTCHA self-unblock.
- **ClamAV-format signatures (0.9.0):** matched inside the agent (no clamd/clamscan
  process, one process in WHM). Uses the databases of an installed ClamAV (cPanel
  plugin, freshclam-updated; official DBs filtered to web/script names) and
  subscription URLs (e.g. the customer's own Malware.Expert license; stored masked).
  Verified live: 52,594 signatures loaded on a cPanel server.
- **CMS:** WordPress/Joomla/OpenCart inventory, outdated/vulnerable components,
  auto-update rules, core checksum verification and **core repair**, DB scanner
  (injected scripts/iframes/PHP in WordPress databases, with snippet and column).
- **cPanel user plugin (0.9.0):** Home (threats stopped, attacks blocked, CMS
  issues, charts), Virus Scanner (full/quick/path + manual scans), Background
  Scanner Logs, Detected Files, CMS Threats, WAF, Bot Attacks — scoped per account.
- **CSF compatibility (0.9.0):** CSF keeps the port filter; csf.allow/csf.ignore
  addresses never blocked by xPGuard; `csfpost.sh` reloads our rules after `csf -r`.
- **Dashboard:** cPGuard-style server cards and server dashboard (protection
  status, threats/web attacks/blocked connections with trend, alerts, charts).
- **Exim RBLs (0.9.0):** barracuda, spameatingmonkey, abuseat, psbl, mailspike
  added to WHM » Exim Configuration Manager (off until enabled).
- **Firewall:** iptables+ipset or nftables, lists, countries, DDNS, port filter,
  DoS, self-healing, live blocked-connection log, CAPTCHA page.
- **Host firewall trust (0.9.0):** portal IPs allowed in CSF/firewalld/UFW/APF/cPHulk/Imunify360.
- **IPDB:** shared attacker blocklist across servers with live monitor and world map.
- **Mass operations**, **Knowledge Base**, **roles & audit log**.
- **Outgoing spam monitor:** Exim per-sender limits, hold/suspend.
- **Reputation:** server IPs on DNSBLs; hosted domains on DBL/SURBL/URIBL/Safe Browsing.
- **Scanner:** own heuristics and behaviour families, hash DB, LMD + YARA feeds,
  ClamAV-format DBs, zip archives, disguised PHP (`.dat/.class/.css/.flv`),
  PHP backups, phishing kits, WordPress core/plugin known-good sets; realtime,
  scheduled and manual scans with live progress; **scan report** like cPGuard
  (0.9.2: files, CMS, DB, target, duration).
- **Trusted services (0.9.0):** search crawlers, monitors, CDN, payment callbacks
  never blocked (firewall, IPDB, auto-bans, WAF bot rules).
- **WAF:** own ModSecurity rules (Apache/LiteSpeed; cPanel hooked via
  `modsec2.user.conf`, like cPGuard), OWASP CRS by default, WHM vendors,
  `SecRemoteRules`, custom rules, per-rule on/off, self-test, WAF logs (select,
  delete, 200 rows, full export), settings laid out like cPGuard's WAF Integration
  (SCANNER, Captcha, Captcha V2, WEBSHELL, AI crawler, **Proxy IP check**,
  Bruteforce, Captcha protected URLs, **Bad Bot blocker** list, whitelisted rules/domains).
- **xgcli:** command line like cPGuard's `cpgcli`.

## 6. How a request flows (example: a setting toggle)

1. UI (`Settings.tsx`) calls `agentCall(serverId, 'settings.set', {waf: {...}})`
   → `POST /api/servers/:id/agent/settings.set`.
2. Portal checks `ACTIONS['settings.set']` (role, timeout) in `routes/agent-cmd.ts`,
   audits mutations, sends the command over the WebSocket.
3. Agent `core.Handlers()["settings.set"]` → `settings.Patch` (normalize + validate)
   → applies side effects (firewall `Apply`, WAF `Apply`, ClamAV reload…) → reply.

## 7. Adding a feature (checklist)

1. Settings: add fields to the struct in `agent/internal/settings/settings.go`
   with JSON names, defaults in `Defaults()`, cleanup in `normalize`, checks in
   `validate`. Secrets: add to `secretFields` and `masked()` in `core/core.go`.
2. Agent logic in the right package; wire it in `core.New`/`Start`.
3. Command: add `h["name"]` in `core.Handlers()` (and a cPanel-user variant in
   `core/panel.go` only if accounts need it, always scoped to their home/user).
4. Portal: add the command to `ACTIONS` in `server/src/routes/agent-cmd.ts`.
5. UI: page/section in `web/src/pages`, types next to it.
6. Tests: Go unit tests next to the code; portal tests in `server/test`.
7. Docs: README feature table, `CPGUARD-PARITY.md` when relevant, this report.
8. Release: bump `VERSION` and `version.go`, commit with the trailer lines
   used in the history, push to the working branch and `main`.

## 8. Build, run, test, deploy

```bash
# agent binaries -> dist/downloads (the portal serves them for install/update)
GOTOOLCHAIN=local scripts/build-agent.sh
# tests
(cd agent && go vet ./... && go test ./...)        # some tests need root (firewall, panel)
(cd server && npm test)                            # PostgreSQL test DB (TEST_DATABASE_URL)
(cd web && npx tsc -b && npm run build)
# local portal
cd server && ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=... PUBLIC_URL=http://localhost:8080 npx tsx src/index.ts
```

- **Portal install/update (production):**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/xmarthost/xmartguard/main/deploy/setup-almalinux.sh -o /root/setup.sh
  bash /root/setup.sh --domain app.xpguard.org --email you@example.com
  ```
- **Agents:** update automatically after a portal update, or per server
  **Update agent**; check with `xmartguard status`.
- **Server install:** Add Server in the portal → one-line `install.sh` with a
  one-time token. Uninstall: `bash /opt/xmartguard/uninstall.sh`.

## 9. Release history

| Version | Highlights |
|---|---|
| M1–0.2 | portal, agent, installer; malware scanner, firewall, reputation, auto-update |
| 0.3 | IPDB, cPanel/WHM plugins, /etc + /opt layout, local socket |
| 0.4 | WAF, CMS + DB scanner, outgoing spam, domain reputation, dashboard, mass ops |
| 0.5 | cPGuard parity pass, AI scanner, CAPTCHA, port filter, CVE feed, process/cron monitors |
| 0.6 | AI API pool, shared knowledge, fleet training, Trim, file viewer, xgcli |
| 0.7.0–0.7.9 | WordPress integrity + core repair, signature feeds, per-rule WAF, faster realtime, LiteSpeed WAF, behaviour families, MCP connector, mobile UI, WAF Rule Sets + OWASP CRS, WAF logs like cPGuard, cPanel hook via modsec2.user.conf, DB scanner detail, themes, loader |
| 0.8.0–0.8.1 | rules from cPGuard scan-report analysis (disguised PHP, backups, phishing); AI clean verdict final for every file type |
| 0.9.0 | CSF compatibility, host-firewall trust, trusted services, ClamAV-format engine, cPGuard-style WAF settings + Bad Bot blocker + Proxy IP check, Exim RBLs, cPanel user plugin |
| 0.9.1 | cPanel plugin tolerates extra output after JSON |
| 0.9.2 | scan report page like cPGuard, dashboard card icons |
| 0.9.3 | saved theme persists (save revert bug, login-page theme) |

## 10. Known gaps and next steps

- **Not yet built:** DirectAdmin and Webuzo plugins (detected only); Lynis
  integration; cloud email scanner; own mass-JS-injection rule (needs 2–3 real
  samples of the `js.downloader` family seen in cPGuard reports).
- **Tested only with fakes/sandbox:** CSF, cPHulk, Imunify360, APF actions;
  whmapi1 vendor calls; official ClamAV databases and trusted-service lists
  (network blocked in the sandbox — verify on a real server).
- **To watch on real servers:** cPanel plugin output (0.9.1 tolerates extra
  output and logs it in the browser console — capture it if it appears);
  ClamAV engine speed with large databases (benchmark ~6.8 MB/s single core on a
  synthetic 60k-signature set); Bad Bot list entries `XX` and `User-Agent` are
  broad substrings (copied from the common hosting list the owner provided).
- `docs/PLAN.md` holds the longer roadmap.

## 11. Lessons and pitfalls (save time)

- ModSecurity 2 rejects `/32` and `/128` in `@ipMatch`/`@ipMatchFromFile`; write
  plain IPs (`waf.modsecAddr`).
- In the sandbox, `pkill -f <pattern>` can kill your own shell; stop the demo
  agent by PID. The demo agent's realtime watcher can make
  `TestRealtimeCatchesExtractedAndMovedTrees` flaky — pause it (`kill -STOP`)
  while running tests.
- `go test … | tail` hides the exit status; check output for `FAIL`.
- The portal reads the built web assets at start: restart it after `npm run build`.
- PostgreSQL may be stopped after a container restart: `service postgresql start`.
- Never add model identifiers to commits or code. Commit trailers:
  `Co-Authored-By: …` and `Claude-Session: …` as in the history.

## Moving the portal to a new domain (xPGuard, 0.10.0)

The product is branded **xPGuard** and the portal runs at
`https://app.xpguard.org`. To move a running portal to a new domain:

1. Point the new domain's DNS at the portal server.
2. Re-run `deploy/setup-almalinux.sh --domain <new domain> --email ...`. It
   updates `DOMAIN` (and so `PUBLIC_URL`) in `deploy/.env`, attaches the new
   domain to a cPanel account with AutoSSL, and keeps the old domain's proxy
   so both names reach the same portal.
3. Agents still connect through the old name. When an agent connects under a
   host other than `PUBLIC_URL`'s, the portal sends it `portal.move`; the
   agent checks that `<new URL>/api/health` answers `{"ok":true}`, saves the
   address in its config and restarts on it. Servers therefore move by
   themselves within a few minutes of connecting; nothing is lost if the new
   address does not answer yet (the agent keeps the old one and is asked
   again on its next connection).
4. When every server shows online under the new name, the old domain can be
   removed.

Internal names were kept on purpose so installed servers keep working:
the service and binary `xpguard-agent`, `/opt/xmartguard`,
`/etc/xmartguard`, `/var/log/xmartguard`, the firewall table, the database
name and the `xmartguard` JSON keys between portal and agent. Everything a
customer, cPanel user or site visitor sees says xPGuard (cPanel/WHM plugin
id `xpguard`, CAPTCHA URLs `/.xpguard/…`, WAF rule messages and tags,
e-mail sender `xpguard@<host>`).
