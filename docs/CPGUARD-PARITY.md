# Parity with cPGuard (study notes)

Written from what a cPGuard installation exposes: its install script, file
layout, cron, readable config/scripts and SQLite schemas. The application
code itself is ionCube-encoded and was not read or decoded. No cPGuard
code, signatures or rules are part of xPGuard.

## Architecture

| | cPGuard | xPGuard |
|---|---|---|
| Runtime | bundled nginx + PHP-FPM 8.1 + ClamAV libs under `/opt/cpguard`, PHP app (ionCube) | one Go binary (`/opt/xpguard/bin/xpguard-agent`), no web server on the host |
| Scheduling | `/etc/cron.d/cpguard`: `crons/main.php` every minute runs a job table (27 jobs) | systemd service with internal schedulers |
| Portal link | agent API on port 9098 reached by vendor IPs | agent keeps an outbound websocket to the portal (no open port) |
| Config | `/etc/cpguard/conf/main.conf`, `config.db` (109 keys) | `/etc/xpguard/settings.json` edited from the portal |
| Data | one SQLite file per module under `app/data` | one SQLite database (`/opt/xpguard/data`) |
| CLI | `cpgcli` | `xgcli` |

## Where things are hooked into the server

| Integration | cPGuard | xPGuard |
|---|---|---|
| ModSecurity on cPanel | `Include /etc/cpguard/cpguard_modsec100.conf` appended to `/etc/apache2/conf.d/modsec/modsec2.user.conf` | same place since 0.7.9: `Include /etc/xpguard/waf/xpguard_modsec.conf` in `modsec2.user.conf` |
| Commercial WAF rules | Malware.Expert through `SecRemoteRules` with cPGuard's license | your own Malware.Expert license: WHM vendor URL, or `SecRemoteRules` key + URL (WAF Rule Sets) |
| Upload scan | `@inspectFile` PHP script | `@inspectFile` shell wrapper calling the agent's scanner |
| Bad bots | `@pmFromFile /etc/cpguard/badbots.txt` | `@pmFromFile` bot lists in `/etc/xpguard/waf/` |
| WAF self-test | test rule `cpg_test_rule` + hourly health check | self-test URL after every change, shown in Rollout |
| WAF hits | read from `modsec_audit.log` every minute | error log + audit log, live |
| inotify | `fs.inotify.max_user_watches = 10000000` in `/etc/sysctl.d/cpguard.conf` | persisted in `/etc/sysctl.d/xpguard.conf` since 0.7.9 |
| CSF | allows vendor IPs, `csf.pignore user:cpguard` | `csf.pignore exe:` for the agent; since 0.9.0 the portal's address in `csf.allow` + `csf.ignore`, CSF keeps the port filter, csf.allow/csf.ignore addresses are never blocked by xPGuard, `csfpost.sh` reloads our rules after `csf -r` |
| Other firewalls | UFW rule for port 9098 | since 0.9.0 the portal's address is allowed in firewalld (trusted zone), UFW, APF, cPHulk and Imunify360; only entries xPGuard added are removed on uninstall |
| WHM / cPanel plugin | `register_appconfig`, `install_plugin` (jupiter) | same |
| DirectAdmin / Webuzo plugin | yes | detection only (planned) |
| Exim RBLs | adds abuseat, barracuda, spameatingmonkey RBL definitions (off) | since 0.9.0: barracuda, spameatingmonkey, abuseat, psbl, mailspike in `/var/cpanel/rbl_info` (off until enabled in WHM); existing definitions are left alone |
| ClamAV | bundles libclamav (`cpg-clamav-libs`) inside its PHP-FPM process and loads Malware.Expert signatures | since 0.9.0 ClamAV-format databases (.cvd/.cld/.ndb/.hdb/.hsb/.ldb) are matched inside the agent (no clamd/clamscan process); installed ClamAV databases are used, subscriptions (e.g. your own Malware.Expert license) by URL |
| Trusted services | — | since 0.9.0 search engine crawlers, uptime monitors, Cloudflare, payment callbacks and vendor servers are never blocked (official lists, refreshed daily) |

## Scheduled jobs (cPGuard → xPGuard)

| cPGuard job | Schedule | xPGuard |
|---|---|---|
| Scanner::dailyScan / weeklyScan / scheduleScan | 01:01 daily, Sunday | daily and weekly scans (settings) |
| DbScan::run | 03:03 daily | DB scanner (daily) |
| WAF::healthCheck | hourly | self-test after each apply |
| Firewall::healthCheck / refreshSets | hourly / 2 h | firewall self-healing loop |
| Firewall::updateDdnsWhitelist | hourly | DDNS allowlist refresh |
| WafProxy::update | 2 h | CDN/proxy real-IP handling (planned) |
| Cms::check / reCheck / wpVerifyChecksum | daily / hourly / daily | CMS scan, WordPress checksum verification |
| Reputation::ip / domain | twice daily / daily | IP and domain reputation loops |
| Lynis::check | daily | not included (rkhunter weekly) |
| UserChecks::process / cron / spam | 5 min / hourly | process and cron monitor, outgoing spam monitor |
| SystemMonitor::check, ServerHealth::check | 5 min / hourly | metrics every heartbeat |
| Report::daily / reportIPs / reportTempBlockedIPs | daily / hourly / 5 min | daily report, IPDB reports |
| AppHealth::* | several | agent health in the portal |

## Records kept per module

| Module | cPGuard columns | xPGuard |
|---|---|---|
| Scanner | identifier, path, reason, definition, user, permission, size, ctime, file/cleanup status | same plus SHA-256, AI verdict, trim |
| WAF | ip, hostname, user, uri, status, method, HTTP version, reason, justification, action, handler, raw log | ip, host, uri, method, rule, reason, justification, action (0.7.8) |
| DB scan | db, table, key column/value, signature id/category/name, snippet, status, detected_at, last_seen | same fields since 0.7.9 |
| Brute force | ip, domain, uri, reason, user | WAF login events + firewall bans |

## Scanner signature families seen in reports

- `{HEX}Malware.Expert.*` — Malware.Expert commercial ClamAV signatures (licensed; not usable by us).
- `{CPG}*.UNOFFICIAL` — cPGuard's own signatures (e.g. perl/python/shell bad scripts).
- `SuspiciousBeta.AI-Malicious` — their AI model (beta).
- `WP.ChecksumFail.*` — WordPress core file that differs from the official checksum (we do the same with official checksums and core repair).

## Full-scan reports from three servers (September 2026)

cPGuard full scans of three production servers (Business600, Business500,
Server1), 4,276 detections from 13–14 September 2026. Only paths, signature
names and statuses were read. No file contents were copied.

| Server | Rows | Quarantined | No action (AI beta) | Main finding |
|---|---:|---:|---:|---|
| Business600 | 216 | 173 | 42 | phishing kits, PHP loaders, SEO spam pages |
| Business500 | 97 | 29 | 65 | mostly AI-beta "suspicious", not acted on |
| Server1 | 3,963 | 3,920 | 42 | one JS downloader injected into 3,832 plugin/theme `.js` files (2 accounts) |

What the reports show:

- 94% of all detections come from Malware.Expert signatures, and 90% are one
  signature: `js.downloader` appended to every `.js` file of two accounts.
- cPGuard's own `{CPG}` signatures are mostly bank phishing kits (Chase, Wells
  Fargo, Bank of America, Navy Federal, Citizens), plus a hidden PHP loader
  copied as `crontrol-82.dat` into ten hidden folders of one site.
- The AI beta flagged 150 files but none was quarantined: it only reports.
- Malware hides under names that are not scripts: `.dat`, `.class`, `.css`,
  `.flv`, `.haxor`, files without an extension in `.well-known/`, and PHP
  backups (`fix.php.backup.20260318120936`).
- Some detections are folders (`Fox-C`, `Fox-C404`) that were disabled
  rather than quarantined.

What xPGuard does with this (0.8.0):

- Scans `.dat`, `.class`, `.css`, `.flv`, `.haxor` and `.tmp` files. A
  malicious PHP program under such a name is a virus (`Disguised.PHPFile`).
- Scans PHP backups (`*.php.bak`, `*.php.backup.<date>`, `*.php.old`) as PHP.
- Own phishing checks: a collector script that mails or sends to Telegram
  three or more secrets (password, card, CVV, SSN, OTP…) together with the
  visitor's IP is a virus (`Phishing.Collector`). A cloned bank or payment
  login page that posts to a PHP file is suspicious
  (`Phishing.CloneLoginPage`).
- Mass JS injection: to write our own rule, we need two or three of the
  quarantined `.js` files. Their names alone are not enough.

## Why no port 9098 and no cron (design choice)

cPGuard runs its own nginx + PHP-FPM on port 9098 so the vendor's servers can
call into it, and a cron job every minute that works through a job table.

xPGuard keeps one outbound connection to the portal instead:

- no open port: nothing on the server listens for the Internet, so there is
  nothing to scan, brute-force or exploit, and no firewall rule is needed;
- the portal reaches the agent through that connection; commands run at
  once instead of waiting for the next cron minute;
- scheduled work runs inside the agent (systemd restarts it if it stops);
  there is no PHP runtime or cron entry to break after a server update;
- trade-off: if the agent process stops, scheduled work stops with it —
  systemd restarts it and the portal marks the server offline so it is seen.

## WAF Integration settings (0.9.0)

Same layout as cPGuard: WAF Integration (with "enabled since"), SCANNER
protection, Captcha protection, Captcha protection V2 (Turnstile or
reCAPTCHA), WEBSHELL protection, AI Crawler protection, Proxy IP check,
Bruteforce & Bot protection, Captcha Protected URLs, Bad Bot blocker (the
common User-Agent list, editable), Whitelisted rules and Whitelisted domains
(chosen from the server's domains).

## cPanel user plugin (0.9.0)

Home (threats stopped, attacks blocked, CMS issues, charts), Virus Scanner
(full, quick and path scan, manual scans list), Background Scanner Logs,
Detected Files, CMS Threats, WAF logs and Bot Attacks — each account only
sees its own files and websites.
