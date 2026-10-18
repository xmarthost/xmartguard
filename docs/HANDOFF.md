# xPGuard: handover for a new session

Read this first in any new chat or Claude Code session that continues the
project. It holds the rules, the current state and what is still open.

## Project

- **xPGuard**: malware scanner, WAF, firewall and IPDB for cPanel/LiteSpeed
  hosting servers. A Go agent runs on each server; the portal at
  `app.xpguard.org` manages the fleet; the sales website is `xpguard.org`.
- Repository: `xmarthost/xmartguard`.
  - `agent/`: Go agent, with packages scanner, waf, firewall, ai, settings,
    notify and store.
  - `server/`: portal API (TypeScript, Postgres, vitest). Its MCP connector
    is `server/src/routes/mcp.ts`.
  - `web/`: portal UI (React, Tailwind).
  - `deploy/`: setup script.
  - `docs/`: notes. See `PROJECT-REPORT.md`, `WAF-RULESETS.md`,
    `TESTING.md` and `AI-TRAINING.md`.
- Current release: **0.22.6** (see `VERSION`).

## Working rules

- **Language**: reply to the owner in Roman Urdu.
- **Branch**: work on `claude/dreamy-davinci-10tcgi`, then push to `main`:
  ```
  git push -q -u origin claude/dreamy-davinci-10tcgi && git fetch -q origin main && git merge-base --is-ancestor origin/main HEAD && git push -q origin HEAD:main
  ```
- **Releases**: bump `VERSION`, run the tests, commit as
  `Release x.y.z: …`, push. Then give the owner the update command:
  ```
  curl -fsSL https://raw.githubusercontent.com/xmarthost/xmartguard/main/deploy/setup-almalinux.sh -o /root/setup.sh && bash /root/setup.sh --domain app.xpguard.org --email support@xmarthost.com --billing-site https://xpguard.org
  ```
  Rollback is the same command with `--branch backup-0.21.34`.
- **Commits**: no AI model names in commits or code. End each commit with
  the session's `Co-Authored-By` / `Claude-Session` trailer.
- **Tests**:
  - Agent: `cd agent && go test ./...`. The WAF tests use real Apache;
    stop and start it cleanly between runs.
  - Server: start Postgres first (`service postgresql start`), then
    `npx vitest run --maxWorkers=4`.
  - Web: `npm run build`. Do not run prettier on web files: it reformats
    whole files.
- **Screenshots**: run Playwright with
  `NODE_PATH=/opt/node22/lib/node_modules`. Reset the test admin with
  `npx tsx src/cli.ts set-password admin@xmartguard.com admin-password-123`.
  No real hostnames in screenshots.

## Hard limits (never break these)

- The project is educational and non-commercial.
- **cPGuard**: never copy its code, signatures, rules or IPDB. Never commit
  cPGuard files. No cPGuard or Imunify branding. Don't decode ionCube.
- **Malware.Expert**: never copy its rules or bypass its anti-scraping.
  Never commit the Malware.Expert serial key (the owner has it; it is not
  in this repo).
- **Keys**: never commit or put in tests the Spamhaus DQS key, the
  AbuseIPDB key or the Turnstile secret.
- **Quarantine samples**: the 200 samples in `/home/bench` stay local and
  are never committed. Tests use harmless fixtures.
- **Content**: never print malware or write exploit payloads. The WAF is
  defensive only.
- **Customers**: they must never see master settings. Security must not get
  in real visitors' way.
- **No automatic learning on servers**: only decisions an admin approved
  reach servers. Auto-exclusions only suggest. New WAF rules start in watch
  mode until approved in Learning Center » Rule approvals.
- **WHMCS**: a WHMCS module (feature 18) is not wanted; customers buy on
  the website.

## How things work (recent, easy to get wrong)

- **ModSecurity chains**: a `ctl:` action runs on its own link's match, so
  it must sit on the **last** link of a chain, never on the first.
  `TestNoCtlOnChainStarters` guards this.
- **LiteSpeed's ModSecurity** does not reliably honour rule removal (by tag,
  ID range or "Allow on this site"). Use a disruptive `allow` instead; the
  WHMCS admin-save rules 7700027 and 7700028 work this way. Raising the
  anomaly threshold with `setvar` does work there (soft blocking proves it).
- **Logged-in WordPress users** are marked once, at the top of the rules
  (`wpUserSetup`, ids 7700046-7700049 and 7701046): `tx.xg_wp_user` (any
  login cookie) and `tx.xg_wp_editor` (a real 32-hex login cookie, or the
  block editor's `X-WP-Nonce` sent same-origin from the site's own
  wp-admin). Rules test these variables, never
  `&REQUEST_COOKIES_NAMES:/…/` (on LiteSpeed, editors were not recognised
  and their saves got 403; fixed in 0.22.6).
- **Learned exclusions**: only an administrator switches one on
  (`Accepted`). Attack-rule exclusions the old "auto" mode switched on by
  itself go back to "suggested" (0.22.6); protocol rules (911-921) stay.
- **CRS settings**: allowed content types (900220) and restricted extensions
  (900240) are set in `agent/internal/waf/level.go`.
- **Bans**:
  - Policy-only blocks (only CRS 920xxx rules matched) never ban.
  - IPDB POST blocks (7700711/7701711) never ban.
  - Requests carrying API auth or signature headers skip the IPDB POST
    rule.
- **Watch mode**:
  - Rules in `waf/monitor.go` `NewRules` and portal patches with `monitor`
    log "[watch]" instead of blocking.
  - Approval goes through `waf_rule_decisions` and is sent to servers as
    `Intel.Enforce`.
- **Spike guard**: a signature with more than 500 detections in an hour is
  paused (`scanner.paused_signatures`). An admin unpauses it.
- **AI distrust**: the AI's clean verdict is only advice, never a restore,
  for:
  - signatures in `agent/internal/ai/untrusted.go`, which include the
    October 2026 fake-plugin campaign (`SplitFunctionName`,
    `EvalDecodedPayload`);
  - risky paths: uploads, core folders, drop-ins, mu-plugins and hidden
    folders.

## Open items

1. **Rule approvals**:
   - Approve 7700510 (shop scraping) and 7700511 (cart spam); their matches
     were all bots.
   - Keep 7700330 watching for about 48 hours after 0.22.3, then review.
2. **Malware campaign**: a fake mu-plugin / three-word-plugin campaign is
   active on business600. Affected accounts include biochemi, biggerbr,
   themagi4, akenterp, uitscom and floareaa. Clean these accounts and change
   their passwords (cPanel and WordPress admins).
3. **920420 on business600**: some hits remain on admin-ajax, xmlrpc,
   Contact Form 7 and wc-ajax. The content type is not logged yet, so look
   at it only if customers complain, and log the content type first.
4. **Not built yet**:
   - M3: uptime/SSL/domain-expiry monitor (14), file versions (15) and
     cPanel plugin v2 (12).
   - M4: targeted virtual patches (07), DB clean (08), outbound monitor
     (09), timeline (10), rule lab (17), Telegram buttons (19), login
     hardening (20) and PHP runtime (06).
   - Other: rule trend charts.
   - Urdu interface: the owner has not decided between Roman Urdu and
     Nastaliq.

## Checking the fleet with the XMart Guard connector

The connector signs in two ways: OAuth (URL `https://app.xpguard.org/mcp`,
Authentication "OAuth"; needed by Claude Code in the cloud; code in
`server/src/routes/oauth.ts`) or a token URL `/mcp/<token>` with "No sign-in".
OAuth access tokens do not expire; revoking on the AI Connector page ends the
connection. The portal vhost proxies `/.well-known/oauth-*` to Node
(`deploy/setup-almalinux.sh`).

The portal's MCP connector ("XMart Guard") offers these tools:

- Read: `list_servers`, `fleet_overview`, `server_dashboard`,
  `list_findings`, `get_finding_content`, `list_scans`, `get_settings`,
  `firewall_events`, `waf_events`, `ipdb_status`, `ai_knowledge`.
- Change: `agent_command`, `start_scan`, `finding_action`,
  `update_settings`, `mark_file`.

`waf_events` filters (0.22.6): `blocked` (403s only), `rule`, `ip`, `host`,
`hours`, `q`, `limit` up to 500, and `before_id` to page back. Results are
compact JSON; a list too long for one answer is shortened and carries
`truncated.next_before_id`. `agent_command` `waf.events` takes the same
fields (`since` as a Unix time instead of `hours`).

Quick check for real editors refused: `waf_events` with `q: "_locale=user"`
(only the block editor sends it) and `blocked: true` on every server.

For a status check of every server, start with `fleet_overview` and
`list_servers`, then run `server_dashboard` on each server. Report:

- online or offline;
- agent version (old ones should update to the current release);
- service problems and alerts;
- paused signatures (`agent_command` `scanner.paused`);
- WAF watch hits (`waf_events` entries starting with "[watch]"; the portal's
  Rule approvals page sums them for the fleet);
- new malware findings.

Use the change tools only after the owner confirms.
