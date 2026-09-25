# XMart Guard — Product Plan

Clean-room security platform for hosting servers, inspired by the capability set of commercial products in this space. No third-party code, signatures, assets or branding are reused; all detection content comes from our own rules or open-source feeds.

## Architecture

- **Portal** (`xmartguard.com`): React UI, Node.js API, PostgreSQL. Stores tenants, users, server inventory, metric rollups, job state and audit history.
- **Agent auto-update**: the portal bundles the agent release (`VERSION`); older agents are updated automatically when they connect.
- **Agent** (`xmartguard-agent`): single static Go binary managed by systemd. Connects out to the portal over TLS WebSocket; authenticates with a per-server Ed25519 key. Detailed security logs stay on the server (local SQLite from M3) and are fetched on demand.
- **Privilege split** (from M3): unprivileged agent + small root helper with an allow-list of typed operations (quarantine move, firewall change, panel hooks). No arbitrary shell execution from the portal.
- **Installer/uninstaller**: one-line, manifest-driven, idempotent, residue report, `--dry-run`.

## Milestones

| # | Milestone | Scope | Status |
|---|---|---|---|
| M1 | Foundation | Portal auth/users/roles, enrollment tokens, agent enroll + signed WebSocket session, inventory (OS/panel/web server/IPs), install/uninstall scripts, server list, overview, audit log, CI | **Done** |
| M2 | Monitoring | System Monitoring (CPU/load/memory/swap/disk/connections/top processes, live mode, history charts), web traffic, alerts on offline/high load | Core done; web traffic pending |
| M3 | Malware scanner | Local SQLite, full/quick/path scans, realtime (inotify), own signatures + ClamAV, quarantine/restore/disable/delete, whitelist/blacklist, daily/weekly scans, Scanner Logs, Virus Scanner settings, email alerts | **Done (v0.2.0)** |
| M4 | Firewall | iptables+ipset (default) or nftables: allow/deny/temp ban/temp allow/ignore/country, LFD-style brute force (SSH/cPanel/WHM/mail/FTP), DoS, Firewall Logs, self-heal after CSF flush | **Done (v0.2.0)**; DDNS + port filter pending |
| M5 | WAF | ModSecurity include with own rules (+ optional OWASP CRS), WAF Logs, bad-bot blocker, CAPTCHA protected URLs, webshell protection, Bot Attacks | |
| M6 | Reputation | IP Reputation (DNSBL, configurable RBL list), Domain Reputation (Safe Browsing/URLhaus), IPDB distributed blocklist + live monitor + world map | IP Reputation done (v0.2.0) |
| M7 | CMS | WordPress/Joomla/OpenCart discovery, plugins/themes, CVE feed, core checksum repair, auto-update policy, DB scanner | |
| M8 | Mail & accounts | Outgoing Spam Monitor (Exim), automatic account suspension, proactive process monitor, cron monitor | |
| M9 | Hardening & alerts | Lynis integration, notifications (Email/Slack/Telegram), daily reports | Email alerts done (v0.2.0) |
| M10 | Fleet ops & billing | Mass Operations with preview/canary/rollback, plans/entitlements | |
| M11 | Panels | cPanel/WHM plugin, DirectAdmin, Plesk, CyberPanel, standalone adapters | |

## Testing strategy

1. Unit tests (Go, TypeScript) and API/integration tests against real PostgreSQL.
2. End-to-end test with the real agent binary against a running portal (`server/test/agent-e2e.test.ts`).
3. Installer end-to-end (`scripts/test-installer.sh`) in CI on a real systemd runner.
4. Real-server test on a disposable cPanel VPS using `installer/selftest.sh` (see `TESTING.md`).
