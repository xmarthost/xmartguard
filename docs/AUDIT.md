# xPGuard full audit (towards a stable release)

Started 2026-10-19. Feature freeze: no new features until this audit is
done (owner's decision). M3/M4 roadmap items are paused.

## Goal

A stable release means: CI green, no open CRITICAL or HIGH finding, every
module below reviewed against the checklist, every fix with a regression
test, and the fleet data (via the connector) showing no new serious
problem after the release.

## Checklist for every module

1. Bugs: logic, races, nil, ignored errors, leaks (goroutines, timers,
   maps, DB connections), IPv6, units, timezones.
2. Security: injection (shell, SQL, ModSecurity, HTML, paths), symlink and
   TOCTOU races as root, tenancy (customer must never reach another
   account or the master's settings), secrets in logs/responses/git, open
   redirects, SSRF, CSRF, rate limits, WAF/CAPTCHA/firewall bypasses.
3. Failure modes: portal down, agent restart, reload failure, disk full,
   proxy retries, 300 servers / 10k domains, LiteSpeed vs Apache.
4. Duplicate and dead code; contradicting options.
5. Agent <-> portal contract (actions, JSON fields).

## Modules (A to Z) and status

| ID | Area | Paths | Review | Fixes |
|----|------|-------|--------|-------|
| A1 | Agent runtime, commands, update | agent/internal/core, cmd, client, protocol, updater, store | running | - |
| A2 | Scanner | agent/internal/scanner, clamdb, ml, wpcore, ai | running | - |
| A3 | WAF | agent/internal/waf | running | - |
| A4 | Firewall, IPDB on server | agent/internal/firewall, hostfw, tor, trusted, reputation | running | - |
| A5 | CAPTCHA, CMS, mail, notify, audit, monitor, panel, settings | agent/internal/... | running | - |
| A6 | Portal security, tenancy, auth, billing | server/src (auth, routes) | running | - |
| A7 | Portal services (hub, IPDB, intel, AI, MCP, CAPTCHA, migrations) | server/src | running | - |
| A8 | Web UI | web/src | running | - |
| A9 | Installer, deploy, update chain, secrets in repo/history | installer, deploy, scripts, CI | running | - |
| A10 | Contracts, settings, duplication, dead code | whole repo | running | - |
| B1 | Automated: go vet, staticcheck, govulncheck, -race, npm audit, coverage | whole repo | pending | - |
| B2 | Fleet data via connector (problems, false positives, errors) | live fleet, read only | pending | - |

## Findings

Each verified finding becomes a GitHub issue labelled `audit` and its
severity, and is listed here with its fix commit.

| # | Severity | Area | Finding | Issue | Fix |
|---|----------|------|---------|-------|-----|
| 1 | MEDIUM | CI | `server/test/fleet.test.ts` failed: CI was red | #2 | a450d7d |
| 2 | HIGH | WAF | Login rules matched only the path end: `/wp-login.php/x` (PATH_INFO) skipped CAPTCHA and brute-force rules | - | 0.22.26 |
| 3 | HIGH | CAPTCHA | One daily pass-cookie value could be shared with a botnet | - | 0.22.26 |

## Status after release 0.23.0 (2026-10-20)

Fix commits are listed per finding in `git log --grep "Audit A"`. Fix
records: `docs/audit/FIXED-A1.md`, `FIXED-A5.md`, `FIXED-A8.md`,
`FIXED-A9.md` (the scanner, firewall and portal fixers were stopped before
writing theirs; their commits name the findings).

| Area | Fixed in 0.23.0 | Still open |
|------|-----------------|------------|
| A1 agent runtime | F3 (part: no downgrade, https only, no redirects; loopback http allowed), F4-F20 | F3 release signing (owner key) |
| A2 scanner (+A1 F1/F2) | F1, F2, F3, F4, F5, F6, F8, F9, F10, F11, F12, F13, F14, F15, F16; A1 F1, F2 | F7, F17 |
| A3 WAF | login PATH_INFO and CAPTCHA pass cookie (0.22.26) | all of F1-F16: the fixes were reverted before release because they weakened blocking in the Apache+CRS tests (editor without same-site proof, IPDB-listed behind Cloudflare); redo one by one with the Apache tests |
| A4 firewall | F1-F8, F10, F12-F14 | F9, F11 |
| A5 CAPTCHA, CMS, mail | F1, F2, F5-F18, F20, F21; F3/F4 via A10 F1 | F19 (part) |
| A6 portal security | F1-F15 | - |
| A7 portal services | F1, F2, F3, F5, F7, F8, F9, F10, F11, F13-F16 | F4, F6, F12, F17, F18 |
| A8 web | F2-F13; F1 server side via A10 F2 | - |
| A9 install/deploy | F2, F5-F11, F12 (actions), F13 | F1 signing, F3 old secrets (owner), F4 (agent side done in A1 F4), F12 images |
| A10 contracts | F1, F2, F3, F4 (part), F5 (part), F6 (part) | F7, F8, F9 |

## Status after release 0.23.1 (2026-10-21)

Fixed since 0.23.0 (each with a regression test; WAF fixes also pass the
13 Apache + OWASP CRS tests, run as root with `XG_DESTRUCTIVE_TESTS=1`):

| Area | Fixed in 0.23.1 | Still open |
|------|-----------------|------------|
| A2 scanner | F7 (a bare file name no longer whitelists code files everywhere), F17 (Recheck and the scan share one content verdict) | - |
| A3 WAF | F1 (forged editor cookie no longer switches the CRS off: admin/REST markers), F2 (PATH_INFO), F3 (behind Cloudflare only CF-Connecting-IP), F4 (forged X-Forwarded-For no longer lets a fake Googlebot pass), F5 (an API header skips the IPDB POST block only on API-looking calls), F6 (settings values checked; bad values never reach the rules), F7 (part: exclusions that work without ctl), F8, F9, F10, F11, F12 (WAF events carry the cPanel account), F13, F15 (custom rules refuse @pmf, @ipMatchF, proxy:), F16 (Bad Bot list drops short and browser words) | F7 rest (scoped exclusions on LiteSpeed), F14 (CAPTCHA redirect with a port in Host: not changed, LiteSpeed's TX macro in redirects is unverified and cPanel sites use 80/443) |
| A4 firewall | F9 (rebuilds keep kernel DoS bans; a solved CAPTCHA changes only its address), F11 (RADb routes only inside the service's known networks) | - |
| A5 CAPTCHA | F19 (withdrawals already coalesced; passes saved together) | - |
| A7 portal services | F4 (CAPTCHA page messages as text, framed only on the CAPTCHA host), F6 (no 0.5 AI endpoint, 2000 files/hour per server), F12 + F17 (agent websocket limits), F18 (dead AI training/review code removed; `min_servers` is not shown in the UI) | - |
| A9 install/deploy | - | F1 release signing (owner key), F3 old secrets in history (owner), F12 images |
| A10 contracts | F9 (one agent.update parameter builder) | F7 (per-server keys win over portal keys: owner decision), F8 (dead handlers and test-only functions: cleanup after the freeze) |
