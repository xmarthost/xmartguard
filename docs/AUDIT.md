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
| 1 | MEDIUM | CI | `server/test/fleet.test.ts` "lists what needs fixing" fails (expects level danger/fix waf, gets warning): CI is red | - | - |
| 2 | HIGH | WAF | Login rules matched only the path end: `/wp-login.php/x` (PATH_INFO) skipped CAPTCHA and brute-force rules | - | 0.22.26 |
| 3 | HIGH | CAPTCHA | One daily pass-cookie value could be shared with a botnet | - | 0.22.26 |
