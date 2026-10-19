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
- Current release: **0.22.26** (see `VERSION`).

## Working rules

- **Every fix is for the whole fleet and for future servers (owner's
  standing rule, pinned).** A false positive or a wrong block found on one
  server is fixed in the engine (scanner, WAF or firewall logic), never
  only by restoring, allow-listing a hash or excluding one site. Restoring
  a file only repairs that copy; the release must make every server,
  including new ones and fresh scans, judge that *kind* of file correctly,
  while the malware next to it is still caught. Each fix gets a regression
  test with an inert fixture of the case (scanner: `fleetfp_test.go`,
  `families_test.go`, `binary_test.go`; WAF: the Apache tests), and the
  report to the owner says what changed in the engine, not only what was
  restored.
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
- **Content type policy** (0.22.7): CRS 920420 is removed at config time
  (`SecRuleRemoveById 920420 930140`) and replaced by our own rule 7700052
  (`contentTypeSetup`), which scores the same but logs the content type it
  refused (`logdata`, shown as "Content-Type: …" in WAF logs). The learned
  920420 exclusions and the iclock and site-beacon rules also remove 7700052.
  930140 (the dot-file rule) blocked real CSS such as `.crush.css`; the
  sensitive-files rule covers the AI tool folders instead.
- **Whitelisted countries in the WAF** (0.22.7): visitors from a
  whitelisted country (portal, Firewall » Whitelist countries) are treated
  like verified visitors (rule 7700054, file `crs-country-ips.txt`): no soft
  block, and CRS blocks only at twice the threshold. They are also exempt
  from IPDB POST blocks. Real attacks still score above the relaxed
  threshold.
- **Answers to the server's own connections** (0.22.9): the firewall
  accepts reply packets (`ct direction reply` / `--ctdir REPLY`) before the
  IPDB, deny, ban and country drops. Before, a site calling a third-party
  API whose cloud address was on the IPDB (seen on business200:
  54.215.31.113, AWS, answering from port 443) never got the answer, and
  the site hung. `TestAnswersFromListedAddressesOnKernel` covers it.
- **CAPTCHA log review** (0.22.17): after 0.22.15 the log showed cloud
  solvers (43.119.x Tencent, 47.82.x Alibaba) refused while passing bot
  addresses for globalincidenttracker.com, but also real people refused
  (CGNAT neighbours 103.70.171.228/229, Cloudflare WARP / iCloud Private
  Relay 104.29.194.57 for 104.29.197.209) and data-centre addresses
  passing ALTCHA on their own address (Hetzner, Scaleway). The ALTCHA
  fallback now accepts the visitor's own network (`sameNetwork`: same
  /24, /48, or both in 104.28.0.0/15) and refuses hosting/cloud
  addresses (AbuseIPDB usage type or score >= 50, cached 7 days, 200
  checks a day; open when no key). 0.22.15 had also reformatted
  captcha.ts, mcp.ts, captcha.test.ts and CaptchaPage.tsx with default
  prettier (double quotes); they are back in the repository's style.
  Never run prettier without the repository's style: there is no
  prettier config, so it rewrites whole files.
- **Background settings apply** (0.22.18): `settings.set` saves and
  returns at once (`apply.state: applying`); the firewall, WAF, DDNS and
  ClamAV apply runs in the background, one at a time, saves made meanwhile
  coalesced into one more run. `settings.apply_status` gives the state;
  the web pages poll it and toast the result, and a failed apply (or one
  running over 15 minutes, or a WAF warning) shows as a "Settings" item
  in the dashboard problems bell. Central config, host trust and the
  tests (`syncSettings`) still apply synchronously.
- **Repeated CAPTCHA passes** (0.22.18): pakshaheens.com showed the same
  visitor passing Turnstile 4 times in 2 minutes. The pass reached the
  agent but LiteSpeed's graceful restart left old processes (keep-alive)
  serving the challenge. A second pass for an address already passed now
  forces a reload (`WAF.RefreshPasses`, at most once per 20 s) and on
  LiteSpeed the pass answer waits `PassSettle` (3 s) so the visitor's
  retry lands on the new processes.
- **WAF settings page speed** (0.22.19): the Rule packages and rule list
  waited for `waf.status`, which counted a week of the WAF log twice (rule
  hits for the catalog and again for the packages) plus four totals: seconds
  on busy servers (business200: ~1M events a week). Counts are now cached a
  minute and refreshed in the background (stale counts served meanwhile),
  warmed at agent start, and the catalog is built once per request.
  `TestPackageCountsCached`.
- **Malware.Expert removed** (0.22.19, owner's decision): no presets, no
  CRS/own-rules replacement, no vendor rules page, no recaptcha/RBL logic,
  no trusted-service entry. Portal refuses ME feeds/vendors and drops stored
  ones on read; agent drops them from any configuration it gets and removes
  (`modsec_remove_vendor`) a WHM vendor it added for ME. Agents that still
  report `own_replaced_by` are resynced and get our rules and CRS back.
  The generic remote-feed and WHM-vendor mechanisms stay.
- **Comment spam** (0.22.20): xmarthost.com/blog had 1,554 comments held
  for moderation (SEO spam: keyword name, HTML link in the text, the same
  shop as website). Three WordPress rules on wp-comments-post.php (also
  WooCommerce reviews), new rules so they only watch until approved:
  7700331 posted without Origin and Referer (every browser sends Origin on
  a form POST), 7700332 an HTML link plus a filled website field (+1000:
  BBCode [url=]), 7700333 four or more "://" in one comment (regex without
  lookahead or deep backtracking). The comment text is logged (logdata) so
  the watch report shows what would be refused. Not done on purpose:
  language or keyword lists (Urdu/Arabic comments are real), CAPTCHA on
  comment POSTs (the comment would be lost). `commentspam_test.go` (also
  through Apache + CRS with XG_CRS_DIR).
- **CAPTCHA domain behind a front proxy** (0.22.21): recaptcha.world now
  points (Cloudflare, proxied) to business600, whose LiteSpeed proxies it
  (External App `xpguard_portal` = https://162.55.6.159:443, `.htaccess`
  `[P]` rule) to the portal on business900, so abuse mail for the domain no
  longer goes to Hetzner. The portal still matches the Host header and
  takes the visitor from CF-Connecting-IP; nothing changed in xPGuard's
  configuration. With the extra hop every visitor reached `GET /v` from
  the same address and shared its 60/10 min limit (429s in the proxy log):
  the page is now limited per visitor (`visitorIP`), like the ALTCHA and
  verify routes. Rollback: point the DNS back to 162.55.6.159.
- **CAPTCHA links with a double slash** (0.22.22): the proxy log showed
  400s for real agent links like `u=//blog/wp-includes/wlwmanifest.xml`
  (a visitor or crawler on site.com//…). `parseParams` now keeps one
  leading slash: the way back is always `https://<h><u>`, so this never
  leaves the site. `/v/verify` still refuses a `//` path sent by hand.
- **Slow CAPTCHA pass / "could not confirm the check"** (0.22.23): on
  LiteSpeed every pass needs a graceful restart, at most one per gap. The
  wait happened inside the reload, after the pass list was rendered, so a
  pass arriving during another's wait went out a full gap later (minute +
  minute + restarts > the portal's 90 s: seen on business100 for
  3dcrafthub.com). `centralPassFor` now waits `WAF.PassReloadWait()` first
  and then renders, so passes arriving meanwhile share the reload; the
  LiteSpeed pass gap is 30 s instead of 60. `TestPassReloadWait`.
- **"The check failed" after ~50 s behind the front proxy** (0.22.24):
  business600's LiteSpeed proxy sent `/v/verify` again while the first
  request still waited for the site's server (LiteSpeed reload). A check is
  accepted once, so the repeat answered "The check failed" and the browser
  showed that, while the first request let the visitor in (passes logged
  at the same millisecond). `/v/verify` now gives a repeat of a request
  still in progress (same link, visitor and solution) the first request's
  answer. Proxy setting: External App `xpguard_portal` Initial Request
  Timeout 120 (more than the portal's 90 s).
- **CAPTCHA bypass review** (0.22.26):
  - Login paths through PATH_INFO: PHP runs `/wp-login.php` for
    `/wp-login.php/x`, and every login-page rule (CAPTCHA gate, central
    CAPTCHA, brute-force counters, XML-RPC, comment spam) matched only the
    path's end, so a suspect skipped the CAPTCHA that way. They now match
    `name(?:/|$)`, decoded (`/wp%2dlogin.php`). `TestLoginRulesPathInfo`,
    Apache cases in `TestCentralSiteMode`.
  - Shared pass cookie: one daily value let one solve open the login pages
    to a botnet. Site mode now uses `captcha.SitePasses`: 8 values a day
    (slots), each pass recorded with the address (IPv6: its /64), state in
    KV `captcha_site_passes`. Rules 7700910+slot log the value a suspect
    sends; `onPassCookie` withdraws a value sent by an address it was not
    given to (new generation, WAF re-applied); holders of that slot solve
    again. `TestSitePassShared`, `TestCentralCaptchaOnSite`.
  - The portal's verify waits up to 20 s for a reconnecting agent before
    "cannot be reached" (seen on business600 at 22:28 on 2026-10-19).
- **CAPTCHA on the website's own address** (0.22.25): CAPTCHA Page »
  "Where the check opens" picks per server (`site_servers`): portal address
  (recaptcha.world, pass list + web server reload) or the website's own
  address (`central_mode: "site"`). Site mode: the WAF sends a suspect to
  `https://<host>:<CAPTCHA HTTPS port>/.xpguard/gate?back=`, the agent page
  shows the portal check in a borderless full-window frame (`&n=&frame=1`;
  portal sets frame-ancestors for that host only), the portal verifies,
  records the event and sends `captcha.ticket` (nonce, IP; single use,
  10 min); the frame postMessages the parent, which POSTs `/.xpguard/pass`
  and gets the `xg_gate` cookie (daily `GateTokens`, rules 7700907/7700908
  check it), so no reload. Lifts a temp ban too. Sites behind the
  Cloudflare proxy cannot reach port 7743: keep those servers on the portal
  address. Also: CAPTCHA events and stats now use `scopeAccounts`, so the
  master sees customer-bought servers' passes and fails.
- **Plugin zips judged like the installed plugin** (0.22.16): on s5,
  `Archive.PHP.Obfuscated.PackedOneLiner` was paused after 911
  quarantines of one file, WP-CLI's download cache
  `~/.wp-cli/cache/plugin/woocommerce-paypal-payments-4.1.3.zip` (same
  sha256 in ten accounts, re-downloaded every minute, AI-restored each
  time). Installed plugin files pass through the official WordPress.org
  checksums (`KnownGoodPath`); zip members never did. `scanZipKnown`
  finds the plugin a zip holds (one `<slug>/` folder, version from the
  main file's header or the zip name) and skips members matching that
  version's checksums (`Scanner.KnownPluginFile`); changed members, mixed
  zips and plugins without public checksums are still checked. The
  signature itself is sound (21 real backdoors on s5). Test:
  `TestFleetPluginZipOfficialMembers`.
- **CAPTCHA page bypass audit** (0.22.15): two ways to pass bots were
  closed. (1) A visitor of the other address family was always allowed
  to solve the page for any address: one IPv6 solver could pass any number
  of IPv4 bots; it now counts toward the 3 other addresses per hour.
  (2) In "auto" mode ALTCHA (proof of work, a script solves it) was
  accepted whenever sent, and the page falls back to it when Turnstile
  errors (headless bots): ALTCHA where Turnstile is the check now passes
  only the visitor's own address, 3 per address per day, for at most 60
  minutes (`captcha.pass` takes `minutes`; the agent never goes above
  its own setting). Turnstile tokens must come from the CAPTCHA host
  (siteverify hostname). The log records the check used (`method`) and
  the solving address (`solver_ip`); the connector has `captcha_events`
  with a summary (solvers passing many addresses, most failed). Agent
  redirects to the page are not stored in WAF events (`isGateRule`), so
  the portal's `captcha_events` is the log to read.
- **DB scanner: fleet review and bulk clean** (0.22.14): the fleet's DB
  Scanner Logs (15 servers, ~500 rows) were mostly false positives:
  WordPress post embeds stored HTML-escaped (`&amp;embed=true`) or without
  the class, Gravity Forms AJAX frames and lazy-load placeholders
  (`src=".../about:blank"`, real source in `data-src`), Jetpack Likes,
  Google Analytics/AdSense/Ad Manager frames, the GA-era
  `document.write(unescape("%3Cscript src='...'"))` idiom, and JavaScript
  around PHP in a WPCode snippet (only code inside PHP tags is judged
  now). Rules version 3 marks them "False positive" at the next scan.
  Hidden iframes in page-builder JSON (`\"`) are now seen. Real ones stay:
  `wp_system_integrity_state` / `*_locale_cache_bootstrap` stored payloads,
  transient-name backdoors, `//div.show/public` 1px frames, hidden ad
  frames. `db.clean` cuts only the reported element out of each row
  (serialized PHP lengths and JSON stay valid), never deletes rows, saves
  the old value in `db_clean_backup`; `db.restore` puts it back. Portal:
  DB Scanner » Clean selected / Clean all / Restore. Tests:
  `TestFleetDBFalsePositives`, `TestCleanStoredValue`,
  `TestCleanDBFindingsMySQL` (real MariaDB, `XG_MYSQL_TEST=1`),
  `TestFleetDocumentWriteUnescape`.
- **Trusted services and the IPDB; exemptions without ctl** (0.22.13):
  the WAF's IPDB POST rule (7700711/7701711) exempts the trusted services
  (search, SEO, AI, monitors, payment, vendors: the WAF groups, not CDNs)
  like the kernel firewall already did; real Bingbot 40.77.167.72 was
  refused `POST /hit` on kuwaitgoldrates.com (business200). LiteSpeed
  ignores `ctl:ruleRemoveById`, so every exemption that removes rules is
  also a marker or a condition in the rule: `tx.xg_api` (API/webhook
  headers, 7700714), `tx.xg_same_origin` (shop filter rules, 7702510) and
  `tx.xg_trusted` in the rules the trusted rule removes (`guardChains`).
  A negated header test (`!@streq`) does not match a request without the
  header: use a marker. Check IP shows a trusted service as allowed.
  `TestExemptionsOnApacheWithoutCtl` strips every ctl from the rules and
  checks on a real Apache; `TestTrustedServicesNotIPDBBlocked` in core.
- **Admin areas of any application** (0.22.12): a save from
  `/admin/`, `/administrator/`, `/adminpanel/`, `/admin-panel/` or
  `/backend/` sent by that admin area's own page (Sec-Fetch-Site
  same-origin, same-host admin Referer, a cookie) gets the editor threshold
  (rule 7700058; only the session threshold on a bad-reputation address,
  7701058). `/dashboard/` and `/panel/` are customer areas and are not
  lifted. Session cookies named by a 32-hex hash (Joomla) count as
  sessions. The older 7700018 exclusion uses `ctl:ruleRemoveByTag`, which
  LiteSpeed ignores; a Joomla administrator on business600 got 403 saving
  RSMembership templates and in File Explorer.
- **Real and fake crawlers** (0.22.8): the bot rules (bad bots, SEO, AI
  crawlers, Bad Bot blocker list) block a crawler name only when the
  visitor is not a trusted service and never on `/robots.txt`. Trusted
  visitors are marked with `tx.xg_trusted` (rule 7700004, and 7700056
  behind Cloudflare from `CF-Connecting-IP` only); the old
  `ctl:ruleRemoveById` alone did nothing on LiteSpeed, so verified Semrush
  and official Ahrefs/GPTBot addresses were still blocked. AI crawlers from
  their official networks (OpenAI, Anthropic `claude.com/crawling/bots.json`,
  Perplexity, Common Crawl, and Amazonbot/Bytespider by reverse DNS) are
  allowed; the same names from elsewhere are fakes ("Fake AI crawler",
  7700503). A customer testing with a browser User-Agent plus "GPTBot" from
  their own connection is a fake and still gets 403.
- **Shared egress networks** (`waf.SharedEgressRanges`: Apple Private Relay
  17.0.0.0/8 and 104.28.0.0/16) never get IPDB POST blocks: many real
  people share each address.
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
- **Vanished files** (0.22.7): open findings whose file no longer exists
  (temp files of a reinfection loop) are closed as deleted at startup and
  when quarantine finds the file gone (`scanner.CloseVanished`,
  `ErrFileGone`).
- **Recheck quarantine** (0.22.7): `agent_command` `findings.recheck`
  (`signature`, `limit`) runs the current scanner over the quarantined copies
  and lists the files it would no longer flag. `findings.recheck_apply`
  (`ids`) restores the listed ones; files the AI cache calls malicious are
  always kept. Run it after scanner false-positive fixes, and restore only
  after the owner approves. Since 0.22.10 it takes `before_id` (page on
  with the returned `next_before_id`; the connector times out after 60 s,
  so use `limit` 200 on big servers) and `ids` (judge only those).
  It judges content only: an ELF judged by name or folder must be looked
  at by hand, and nothing from a hacked account is restored (pakshahe on
  business200 had a botnet program in `wp-rocket/vendor/monolog/`).
- **Scanner false positives fixed in 0.22.10**: empty `auto_prepend_file`
  settings (cPanel's MultiPHP INI editor writes `= ""`); a site's own forms
  that mail the visitor (`PHP.Spam.Mailer` now needs a standalone script or
  tester signs such as `error_reporting(0)`, self-delete or `goto`; since
  0.22.11 also any form whose recipient and subject both come from the
  request, an open relay);
  base64 certificates and keys (composer/ca-bundle, payment callbacks).
  ELF programs in a `vendor/` folder under wp-content are flagged again
  unless they are image tools (`cwebp-…`) or libraries.
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
3. **Content type blocks on business600**: about 800 a day on wc-ajax,
   admin-ajax, Contact Form 7 and Joomla register. Since 0.22.7 rule 7700052
   logs the content type: check `waf_events` `rule: 7700052` and add the
   missing type to `AllowedContentTypes` if it is a real one.
4. **Still open from the 0.22.6 review**: mrwowea `tg_relay` (920540),
   hapetsupplies admin-ajax from a Pakistani IP (942100), digimedia-verse.
5. **Scanner false positives**: fixed in 0.22.10 and the verified files
   restored (business500, 200, 600, 700, 900). Still to look at:
   `td-subscription/includes/tds_ajax.php` (adsanews, business500) and
   recheck business100, server1 and superfast page by page.
6. **Reinfection on s5**: uitscom and ebwaccounting re-drop
   `ridge-compiler-live.php` about every 10 minutes. Clean these accounts
   (look for the dropper in cron, mu-plugins and the database) and change
   their passwords.
7. **Not built yet**:
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
