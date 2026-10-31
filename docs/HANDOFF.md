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
- Current release: **0.24.15** (see `VERSION`).

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
- **Branch**: work on the session's branch (0.23.5:
  `claude/keen-wozniak-eebt73`, 0.23.6 to 0.24.15 too), then push to `main`:
  ```
  git push -q -u origin <branch> && git fetch -q origin main && git merge-base --is-ancestor origin/main HEAD && git push -q origin HEAD:main
  ```
- **Releases**: bump `VERSION`, run the tests, commit as
  `Release x.y.z: …`, push. Then give the owner the update command:
  ```
  curl -fsSL https://raw.githubusercontent.com/xmarthost/xmartguard/main/deploy/setup-almalinux.sh -o /root/setup.sh && bash /root/setup.sh --domain app.xpguard.org --email support@xmarthost.com --billing-site https://xpguard.org
  ```
  Rollback is the same command with `--branch backup-<version>` (for
  0.24.15: `--branch backup-0.24.14`; see "Rollback" under 0.24.15 below);
  agents never downgrade on their own (0.23.0), so they are put back by
  hand.
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

- **Release 0.24.15: probe lines in the WAF log** (2026-10-31).
  business600 (agent 0.24.13 at 10:03 UTC, 0.24.14 at 10:10 UTC; each
  result checked to come from that version by its new probes): `scores`
  refused for both test saves under every threshold, even 100, while the
  ways' XSS body passes under 10000. The customer's real saves scored 10
  on that server (08:20-08:28 UTC, the last ones; none since the
  updates, and no CJ request on business900 since). So something other
  than the score compared with the threshold refuses them, or the
  threshold is read differently; unknown, because self-test lines were
  dropped from the log. Now lines of /xpguard-crs-selftest/... probes are
  kept as category "selftest" (rule, message with the total score),
  never counted, banned, learned (learn.go) or in the monthly report;
  the XSS body has score probes too (7700870-7700874). Next: read the
  "selftest" rows on business600 (waf_events q "/score/") and decide from
  the refusing rule.
  - **Rollback**: `backup-0.24.14`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.14: score probes** (2026-10-31). business600 on
  0.24.13: lifts still refused. `ways`: cond_request_uri and
  cond_filename_end pass, cond_query_string and cond_args_get refused
  (LiteSpeed fills neither QUERY_STRING nor ARGS_GET). Every link of the
  WooCommerce and Joomla lifts now passes alone, so the likeliest cause
  left is the score: LiteSpeed has no libinjection and may score the test
  saves above 30 / 60. The self-test now posts both test saves under
  fixed thresholds 20, 30, 45, 60, 100 (rules 7700850-7700864,
  /xpguard-crs-selftest/score/<joomla|wc>_<t>) and reports
  `self_test.scores`. Next: if a body passes under its lift's threshold
  but the lift is refused, the chain is at fault; otherwise raise the
  thresholds for these authenticated saves on LiteSpeed.
  - **Rollback**: `backup-0.24.13`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.13: LiteSpeed reads no ARGS_GET** (2026-10-31).
  business600 `ways` on 0.24.12: cond_tx_lt, cond_tx_count and
  cond_args_names (phase 2) pass, so the "@lt" guard was not the cause
  (0.24.12 removed it anyway; harmless with the lowest-first order);
  cond_args_get (`ARGS_GET:k`) is refused: LiteSpeed's engine does not
  fill ARGS_GET. The WooCommerce API rule read the key from ARGS_GET; it
  now reads `REQUEST_URI` ([?&]consumer_key=ck_…). The Joomla rule's
  every link passes alone except its path test, `REQUEST_FILENAME "@rx
  …administrator/(?:index\.php)?$"` (probes used @beginsWith): probably
  the "$" anchor; it now tests REQUEST_URI up to the query. New probes:
  cond_filename_end, cond_query_string, cond_request_uri.
  - Open: 14 other uses of ARGS_GET in the WAF rules (customizer,
    theme colour CSS, beacons, central CAPTCHA …) are likely dead on
    LiteSpeed; move them to REQUEST_URI/QUERY_STRING once the probes say
    which is read.
  - **Rollback**: `backup-0.24.12`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.12: relaxations without the "@lt" guard** (2026-10-31).
  business600 (LiteSpeed) `self_test.ways` on 0.24.11: none 403;
  thr_single, thr_chain, thr_phase2, remove_949110, detection_only,
  allow "passes"; remove_xss_tag refused. So LiteSpeed does honour a
  chained rule setting the threshold. The one link every relaxation had
  and no passing probe had: `SecRule TX:inbound_anomaly_score_threshold
  "@lt N"` (raise only, never lower). It is gone from all of them (the
  setvar sits on the previous link), and the setups run lowest first
  (WooCommerce API 30, session 30, editor and admin area 100000, Joomla
  token 60 in phase 2, WHMCS app saves 100000 last), so a later one never
  lowers an earlier, higher one. Known cost: at level low (CRS 20,
  verified visitors 40) a session request now gets 30. New cond probes
  check each remaining link type on the engine: cond_tx_lt (the removed
  guard, to confirm), cond_tx_count (&TX:xg_strict), cond_args_get
  (ARGS_GET:k), cond_args_names (ARGS_NAMES, phase 2).
  `TestCustomerFalsePositivesWithCRS`: a Joomla save with the token and
  no same-site headers, or from another site, passes the WAF since 0.24.8
  (Joomla refuses a forged token); without the token it is refused.
  After the update read business600 `self_test.lifts` (both should pass)
  and `ways`.
  - **Rollback**: `backup-0.24.11`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.11: which relaxations LiteSpeed honours** (2026-10-31).
  0.24.10's self-test, same rules on both servers:
  business700 (Apache) `lifts` joomla_admin_save and
  woocommerce_api_write "passes"; business600 (LiteSpeed) both "refused
  (HTTP 403)". So on LiteSpeed's engine raising
  tx.inbound_anomaly_score_threshold from a chained rule does nothing:
  every threshold relaxation of xPGuard (session, editor, admin area,
  WHMCS, Joomla, WooCommerce API) may have been without effect on the
  LiteSpeed servers (most of the fleet). The self-test now also posts the
  same weak attack to /xpguard-crs-selftest/mech/<way>, each relaxed in
  one way by rules 7700080-7700086 (`mechProbes`): thr_single (one
  SecRule setting the threshold), thr_chain, thr_phase2, remove_949110
  (ctl:ruleRemoveById), remove_xss_tag (ctl:ruleRemoveTargetByTag),
  detection_only (ctl:ruleEngine), allow; "none" is the control
  (403 at levels normal and strict). Results in waf.status
  `self_test.ways`. Next: read business600's `ways` and move the
  relaxations to a way LiteSpeed honours.
  - **Rollback**: `backup-0.24.10`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.10: duplicate WAF rule ids** (2026-10-31). 0.24.9's
  WooCommerce API rule used 7700065, which the soft block's IPDB marks
  (`IDSoftStrictIPDB`+i: 7700064-7700066) already use, and 0.24.8's Joomla
  rule used 7700063 (`IDMarkSuspect`+1, the CAPTCHA suspects). On
  business900 cPanel's Apache configuration check refused the rules
  ("Found another rule with the same id") and the portal setup stopped.
  LiteSpeed accepts duplicates and may keep only one of them, which can
  explain why the Joomla relaxation never applied on business600. Now
  `IDJoomlaAdmin` = 7700070 (+1000) and `IDWCRestKeys` = 7700072 (+1000,
  +2000); 7700070-7700099 were free. New Apache test
  `TestEveryRuleIDOnceOnApache` turns every feature on (soft block,
  CAPTCHA suspects, IPDB marks, trusted and country lists, CRS) and fails
  on a repeated id; it fails with 0.24.9's id. Lesson: derived ids (+i,
  +1, +1000, +5000) are not in a grep of the constants; run this test
  for every new rule id.
  - **Rollback**: `backup-0.24.9` has the duplicate ids; roll back to
    `backup-0.24.7` instead if needed.
- **Release 0.24.9: WAF relaxations checked on every server; WooCommerce
  API writes; JExtStore license address; CJdropshipping** (2026-10-31).
  - joomlash (business600, 0.24.8 installed): File Explorer (score 40),
    Global Configuration (10) and Admin Tools .htaccess Maker (10) still
    refused on 2026-10-31 08:20-08:28 UTC, so 7700063 (Joomla form token,
    phase 2) did not apply on LiteSpeed either, while it passes on Apache
    with CRS 4.18 and 4.30. The token is now read from ARGS_NAMES (the
    collection CRS itself reads) instead of ARGS_POST_NAMES. Not proven
    on LiteSpeed: the WAF self-test now posts what the relaxations are
    for (`liftChecks`: a Joomla admin save with a token, a WooCommerce API
    product write with keys) and reports `self_test.lifts` in waf.status
    ("passes" or "refused (HTTP 403)"). Read it on business600 after the
    update before changing anything else.
  - WooCommerce REST API writes with the shop's API keys
    (`wcRestKeysSetup`, 7700072/7701072/7702072 since 0.24.10: consumer_key, OAuth
    consumer key, Basic authentication; POST/PUT/PATCH/DELETE to
    wc/v1-3) are refused from score 30. ssshoesmaker.com (business900):
    CJdropshipping's product listing refused as XSS (941100, 941160,
    920250; score 13-15, 18 times); server1 bestofpk.com's products/batch
    sync (932370, 15) the same way. Without keys, keys on another route,
    and an attack with keys are still refused.
  - Trusted services: `cjdropshipping` (vendor group: firewall, IPDB, bans
    and the WAF's bot rules never block it) with the three addresses CJ's
    support gave (47.254.74.208, 47.88.4.204, 47.254.34.239). They were
    on no list; the CRS was what refused them.
  - Scanner: JExtStore's extensions (JSitemap Pro AjaxserverModel.php,
    JComments, GDPR … zips in jdownloads) build their license and update
    address with str_rot13 spelled in pieces ('str_' . 'ro' . 't' . '13'
    on 'uggc' . '://' . 'fgberwrkgrafvbaf' . '.bet'). `splitDecodesURLs`:
    no SplitFunctionName when the file has no eval/assert and every call
    of the assembled decoder (str_rot13, base64_decode) takes constant
    strings that decode to a web address and is not called itself. Read
    in full (95 KB, MCP paging): vendor code, clean.
  - Open: Akeeba Kickstart restore.php (330 KB, FileDropper) not read in
    full yet. The customer asks to exclude the whole jdownloads folder:
    not done (owner's decision; it holds extension packages the site
    hands to its visitors).
  - Tests: Apache `TestAdminAreaSavesWithoutRuleRemoval` (WooCommerce
    cases), `TestCRSSelfTestEveryLevel` (lifts), CRS 4.18 and 4.30;
    `TestFleetJExtStoreLicenseAddress` (fails on 0.24.8).
  - Setup script: on business900 (portal host, LiteSpeed) the update
    stopped at "Apache mod_proxy_http is not available" after the portal
    had already restarted on the new code: `httpd -M` listed no modules
    there. mod_proxy_http is now found by its EasyApache package or module
    file first.
  - **Rollback**: `backup-0.24.8`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.8: Joomla admin saves on LiteSpeed, Joomla page cache**
  (2026-10-31). Customer joomlash (business600: joomlashare.ir/.net/.org,
  joomlashares.com, fajoomla.ir, joomlatranslate.com/.ir, proshare.ir;
  behind Cloudflare).
  - WAF: after 0.23.32 the customer's own administrator saves were still
    refused (2026-10-27/28, address 64.204.164.x, not on any list): Admin
    Tools' .htaccess Maker (932260 + 932160, score 10), Global
    Configuration (941100 + 941160, 10), File Explorer (30), jDownloads
    (25), RSForm (10). Neither the admin-area lift nor the session lift
    (threshold 30) applied, though both should have: on this LiteSpeed
    engine a header condition (Sec-Fetch-Site or Cookie) does not match.
    Not proven (no request headers in the log). New `joomlaAdminSetup`
    (7700063, phase 2): a POST to /administrator/ (index.php) with
    Joomla's form token (a field named with 32 hex characters) is refused
    from score 60 on (`joomlaAdminThreshold`); on an address with a bad
    reputation 30 (7701063). No header needed. The same body without the
    token, a token-shaped field on the front end or in another admin
    file, and an attack tool's request (score 60+) are still refused. The
    sites get daily SQL injection (com_phocacart) and secret-file probes:
    the WAF stays on for them.
  - Scanner: Joomla page cache files (administrator/cache/page/*.php:
    `<?php die("Access Denied"); ?>#x#` and the saved page, code samples
    and all) were quarantined as `PHP.Suspicious.EncodedPayload` again and
    again. `inertPHP` now reads die/exit with a plain string (no `$`, no
    backslash) or `?>` as stopping at once, not a phar (`__HALT_COMPILER`),
    and such a file is not judged by its text (analyze, Match); hash, ClamAV
    and LMD bytes still apply.
  - Portal MCP: `get_finding_content` takes `offset` and pages a file in
    40,000-character parts (`content_next`). JSitemap Pro's
    AjaxserverModel.php (95 KB, `SplitFunctionName`, AI 60 % "clean") and
    Akeeba Kickstart's restore.php (330 KB, `FileDropper`) still flag on
    0.24.5 and could not be read past the first 40-60 KB: read them in
    full after this update before any restore or engine change. Both come
    from "Pro" packages on a site that shares commercial extensions
    (nulled packages often carry backdoors). The customer's own restores
    (cPanel plugin) do not clear content for the server (by design), so
    their files came back to quarantine a minute later.
  - Tests: Apache `TestAdminAreaSavesWithoutRuleRemoval` (new cases),
    `TestFleetJoomlaPageCache` (fails on 0.24.7), server `pages a long
    file content`.
  - **Rollback**: `backup-0.24.7`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.7: server dashboard opens at once** (2026-10-31). A
  server not opened for a while took 10 s and more: `dashboard.get`
  counted whole tables (millions of WAF events) on every open, on the
  agent's only database connection (2M events: 7.4 s). Now the agent keeps
  the answer per period (`dashcache.go`): an open gets the kept one at
  once, one older than a minute is counted again in the background, and
  the 30-day view is counted every 10 minutes (first at 2 minutes after
  start), so even a first open shows numbers at most minutes old. The
  all-time totals come from the server card's counts (two fewer passes).
  The answer carries `updated_at`; the page shows "Updated ... ago" and,
  when it got old counts, asks again after 10 s (up to 3 times).
  Tests: `TestDashboardKeptAndRefreshed`, `TestDashboardUpdatedAt`.
  - **Rollback**: `backup-0.24.6`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.6: false positives of the full scans of 2026-10-30**
  (all servers; reviewed while the scans ran).
  - `Htaccess.Hacked.SearchCloaking` (0.24.2) took Softaculous's "Enable bot
    protection" block for cloaking: Baiduspider among AhrefsBot, SemrushBot,
    MJ12bot... sent to http://no.access/; root .htaccess files were cleaned
    (bot block removed). Now a user-agent list with three or more bad-bot or
    scraper names is a blocklist, and targets that go nowhere (no.access,
    localhost, 127.0.0.1) are blocks. business300 deversco's four restored.
  - `PHP.Webshell.Uploader` (0.24.2) on Chamilo's upload.document.php:
    `move_uploaded_file_collection_into_directory(` read as
    move_uploaded_file and the sent name used elsewhere. Now a real
    move_uploaded_file() whose destination is built from the sent name
    (directly or through variables) is needed.
  - Older rules: `PHP.Backdoor.EvalInput` on assert(is_string($v)) of
    request data (OpenTelemetry, php-saml: a type check runs no code; an
    eval inside it is still read); `PHP.Backdoor.CommandInjection` on a
    method named exec (Afterlogic DAV) and exec('whoami') (Yii debug);
    `PHP.Backdoor.FileDropper` on a canvas image from a data URI (Chamilo
    badges; not when the written path comes from the request) and on a
    debug log of cookies (Retina Images; not when the file then includes a
    data file or a variable).
  - Real and kept: ClickFix kit files (server100 ftech), hidden payloads,
    fake-plugin campaign zips, Telegram phishing pages, kit .htaccess locks
    in fake wp-includes folders and in plugin data folders
    (ecommupscale: the kit overwrote WooCommerce wc-logs, CF7 and JetBackup
    deny files; those folders need their deny back), sci-calc.php (eval of
    a typed expression: vulnerable code, left flagged).
  Tests: `TestFleetLibrariesOfFullScan` (fails on 0.24.5), cloaking
  look-alikes in `TestFleetHtaccessCloaking`.
  - **Rollback**: `backup-0.24.5`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.5: review of parts 1-4** (2026-10-30). The owner asked
  for parts 1-4 and the system around them to be checked again for
  mistakes and overlaps. Found and fixed:
  - The database scan marked every detected row of a site gone before
    finding them again, also the integrity watch's rows (only the plugin
    watch's were kept): each DB scan re-notified every modified plugin.
    `markDBGone` keeps both watches' rows.
  - The "DB infected" count (portal) and a site's `db_issues` counted the
    admin, plugin and integrity watch rows as infections; they now count
    infections only (the rows stay listed).
  - wordpress.org not answering: the plugin watch would call every plugin
    unknown (three or more plugins and none with a release is a failed
    lookup: skipped, earlier rows kept), and the integrity watch would mark
    earlier rows cleaned (kept unless the release has no sums, 404).
  - The login CAPTCHA for hosting networks ignored the whitelisted
    countries (ignored_countries, the owner's PK), which the rest of the
    central CAPTCHA treats as a full whitelist: they are now dropped from
    the hosting list.
  - Checkout attempts (7700407) were counted in "logins in 24 h"; they
    still count toward the ban.
  Checked with no change needed: no WAF id, rule-list entry, scanner
  signature or audit check name used twice; the WooCommerce exclusion
  (7700014) removes PHP-injection rules only; 0.24.4 rules loaded and the
  WAF self-test passed on business500 and server1.
  Tests: `TestPluginIntegrity` (DB scan, wordpress.org down, counts),
  `TestPluginWatchLookupsFailed`, `TestWhitelistCountryDropsHostingNets`,
  checkout in the WAF log test.
  - **Rollback**: `backup-0.24.4`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.4: security plan part 4 - card testing and server
  checks** (2026-10-30; last part of the plan).
  - WAF 7700407 counts WooCommerce checkout POSTs (Store API
    `/wc/store[/vN]/checkout`, `?rest_route=`, `?wc-ajax=checkout`) like
    failed logins: card-testing bots reach the brute-force ban (10 in 10
    minutes by default), a shopper's order or two never does. The Store
    API exclusion (7700014) removes PHP-injection rules only, not this.
  - Audit `php`: a php.ini whose disable_functions lists none of exec,
    shell_exec, system, passthru, proc_open, popen (medium), or blocks them
    but leaves putenv (LD_PRELOAD bypass with mail(), low); the last
    disable_functions line counts.
  - Audit `isolation`: net.ipv4.tcp_syncookies off. Audit `realtime`:
    folders realtime protection cannot watch (inotify limit; the fleet
    sits near 999,000 watches) and lost-event counts, with the sysctl to
    raise.
  - Checked on the fleet after 0.24.3: all servers on 0.24.3; 7700406
    counted its first application-password guess (server100,
    /wp-json/wp/v2/users/me); 7700316 no hits.
  - Plan items not done (owner decision or larger work, see
    `docs/SECURITY_PLAN.md`): signed releases, per-plugin patch feed, IP
    classes and cookie-bound passes (I6/I7), per-site budgets and
    under-attack mode (M10), client fingerprints (M13), HTTP/2 abuse (M11),
    Web Bot Auth and Private Access Tokens (M12/M22), AI crawler budgets
    (I9), egress monitor (M14), 2FA (M17), DoS limit on by default (I10:
    owner's choice; only audited), skimmer and blockchain-loader families.
  Tests: `TestCheckoutTryRule`, `TestDisableFunctionsAndSyncookies`,
  `TestRealtimeCoverage`.
  - **Rollback**: `backup-0.24.3`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.3: security plan part 3 - answer new holes faster**
  (2026-10-30).
  - WAF 7700316 (watch until approved): `role`/`roles`/`user_role`/
    `new_role`/`default_role`/... = administrator outside WordPress's own
    user screens (user-new, user-edit, users, profile) and the core REST
    users route. No cookie exception (one is easily added).
  - Plugin integrity (`cms/integrity.go`, with the CMS core check): each
    wordpress.org plugin's PHP files against the release's SHA-256 sums
    (downloads.wordpress.org/plugin-checksums, cached per release);
    `WP.Plugin.ModifiedFiles` (category `integrity`) lists changed and
    added PHP files; cache/logs folders skipped; never cleaned.
  - Audit `kernel` (a newer kernel installed than running: reboot pending;
    low with KernelCare) and `isolation` (fs.protected_symlinks/hardlinks,
    CloudLinux SecureLinks sysctls off; /proc without hidepid when there is
    no CageFS). Read-only, no CVE build list invented.
  - WAF 7700406 counts REST requests with Basic authentication refused
    (401) as failed logins: application-password guessing reaches the
    brute-force ban.
  - Process lineage (`monitor`): a shell whose parent is lsphp/php-fpm/
    php-cgi/php running over 2 minutes, not a backup or build tool, is
    Suspicious (alert; killed only by the existing CPU rule).
  - Not done, owner or later: signed releases (the updater only checks a
    sha256 from the same portal; signing needs a key the owner keeps
    outside the repo), a patch feed per unpatched plugin (needs each
    exploit's request shape; portal patches 7703xxx stay the way),
    phpMyAdmin/Roundcube jails, card-skimmer and blockchain-loader script
    families.
  Tests: `TestAdminRoleArgRule`, `TestPluginIntegrity`,
  `TestKernelAndIsolation`, `TestAppPasswordLoginRule`, `TestShellFromPHP`.
  - **Rollback**: `backup-0.24.2`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.2: security plan part 2 - malware and persistence
  breadth** (2026-10-30).
  - DB: a ClickFix page kept in a post, option or widget
    (`DB.Phishing.ClickFix.FakeVerification`, category `phishing`; the
    cleaner refuses it: the whole value is the page). `scanner.ClickFixPage`.
  - `.htaccess` cloaking (`Htaccess.Hacked.SearchCloaking`): visitors from a
    search engine (HTTP_REFERER) sent to another site, or crawlers
    (HTTP_USER_AGENT) given another site or a PHP doorway. Not: target `-`
    (LiteSpeed Cache's crawler vary), prerender services, `%{HTTP_HOST}`
    targets, negated conditions, mobile redirects, hotlink/bad-bot blocks,
    index.php. The cleaner drops these groups (`kitGroups`, with the
    ClickFix redirect) and keeps the site's rules.
  - Audit: `persistence` (authorized_keys changed in 7 days - key comments
    only, never key material; systemd user units; a shell profile line that
    downloads and runs, decodes and runs, or opens /dev/tcp; at jobs of
    hosting accounts), `world_writable` (0777 folders in webroots, sticky
    ones not), `exposed_repo` (a .git repository with config in a website).
  - WAF, watch until approved: 7700606 base64 PHP command in a cookie
    (no logged-in exception: a fake cookie would bypass it), 7700607 POST to
    an image, icon or stylesheet (polyglot shells).
  - 0.24.1 (in this part): chattr +i shells quarantined; quarantine week.
  - Open, moved to part 3: card-skimmer and blockchain-loader script
    families (files and DB).
  Tests: `TestDBClickFixPage`, `TestFleetHtaccessCloaking`,
  `TestPersistenceAndWritableFolders`, `TestCookieShellRule`.
  - **Rollback**: `backup-0.24.1`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.1: quarantine kept a week, then deleted; locked shells
  quarantined** (2026-10-30).
  - Owner's rule: a quarantined file older than `quarantine_days` (7) is
    deleted, also what was quarantined before 0.23.31 (that release's
    grace week is gone), and the next ones as they age. 20,000 files a
    round; rounds an hour apart while a backlog is left (business300 held
    560,000), else 6 hours (`pruneOld` reports the backlog).
  - Kits lock their shells (and the folder) with chattr +i so the move
    fails with EPERM and the file stayed "detected". Quarantine and delete
    now clear the immutable and append-only flags of the file (they stay
    cleared) and of its folder for the move only (put back after: an admin
    may lock a folder on purpose). `pinned.unlocked`; the folder handle is
    O_PATH, so it is reopened for the ioctl.
  Tests: `TestQuarantineKeptAWeek`, `TestQuarantineLockedFile`.
  - Checked on the fleet after 0.24.0: all 17 servers on 0.24.0; RADb
    reachable (trusted lists from RADb refreshed); server1's audit has no
    stack_cve item (panel, LiteSpeed, Exim, Roundcube patched). Admin and
    plugin watch report with each site's next CMS scan (server1: every 72 h).
  - **Rollback**: `backup-0.24.0`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.24.0: security plan part 1 - stop the attack chains seen on
  the fleet** (2026-10-30; plan in `docs/SECURITY_PLAN.md`, four parts,
  each released and installed before the next).
  - **Admin watch** (`cms/admins.go`, with the DB scan): per site,
    `WP.Admin.New` (not in the site's baseline; at the first read, one
    registered in the last 30 days other than the first user),
    `WP.Admin.Suspicious` (adm + random, a hex tail, a look-alike of admin,
    mail at example.*/.local/wordpress.org), `WP.Admin.Farm` (more than 20
    such, or over 50 admins: one summary row and 20 named rows). Baseline
    table `cms_admins`, never learned again: a new admin stays reported
    until archived or demoted. Nothing is changed in the site; the DB
    cleaner refuses these rows.
  - **Plugin watch** (`cms/pluginwatch.go`): `WP.Plugin.NewUnknown` (after
    the first listing, not on wordpress.org or claiming a version newer than
    it), `WP.Plugin.TimestampClone` (`name_<unix time>`). Baseline table
    `cms_plugin_base`. Realtime tells it within 2 minutes when a folder
    appears in `wp-content/plugins` (`Realtime.OnPluginDir`, no updates or
    saving at that time).
  - **Logins from hosting networks** (`captcha.hosting_login`, default on;
    `hostnets`): ~40 hosting/cloud/VPS AS numbers, routes from RADb daily
    (wide or nested routes dropped, at most 60,000), file
    `captcha-hosting.txt`; rule 7700069 marks visitors of the site login
    URLs (not xmlrpc.php) from those networks as CAPTCHA suspects, except
    `captcha-hosting-exempt.txt` (allowed/ignored/passed addresses, the
    fleet, the server's IPs) and trusted services. Needs the central
    CAPTCHA; sites behind Cloudflare are not covered (the address is
    Cloudflare's).
  - **Panel audit** (`audit/stack.go`, check `stack_cve`): cPanel < 11.136.0.32,
    LiteSpeed Enterprise < 6.3.7 (OpenLiteSpeed skipped), Exim < 4.99.2,
    Roundcube < 1.6.11 (1.5.x < 1.5.10). Read-only.
  Tests: `TestAdminWatch`, `TestAdminWatchBaseline`, `TestPluginWatch`,
  `TestHostingLoginRule`, `hostnets.TestRefresh`, `TestStackCVEs`,
  `TestRealtimeReportsNewPluginFolder`.
  - **Rollback**: `backup-0.23.42`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.23.42: plugins uploaded with known passwords; new links seen
  by realtime protection** (2026-10-30). server1, 2026-10-28: logins with
  passwords the attacker already had (each the first POST, a 302; no
  failed logins, so brute-force protection had nothing to count), then
  wp-admin's plugin uploader. None of the five files had a finding. New
  rules (`scanner/plugininject.go`, built from how each works):
  - `PHP.Backdoor.SelfHidingInjector` ("wp-warden"): removes its own entry
    from the plugin list unconditionally (`all_plugins`, unset
    plugin_basename(__FILE__)) and prints a script on front-end hooks, its
    tag cut in two or from a 20 KB base64 block. A plugin hidden by a
    setting (MainWP) or a white-label plugin with no visitor script is no
    finding.
  - `PHP.Injector.HiddenScriptURL` ("WP-CORE"): byte arrays turned into a
    URL by XOR with a key, loaded with wp_enqueue_script.
  - `PHP.Webshell.Uploader`: a page with its own upload form saving the
    file under the name it was sent with, checking neither the file nor
    the sender. `PHP.Webshell.FileManager`: file operations with
    open_basedir / disable_functions switched off from the script.
    `PHP.Obfuscated.EscapedInput`: request variables read by escaped names.
  - Realtime: symlink() makes a link without writing a file, so links were
    only found by full scans (the theft farm was made again after scan 50
    quarantined 231,822). IN_CREATE of a link now queues it, catch-up walks
    include links, and `ScanFile` judges a link (`scanLink`); a link an
    administrator restored or ignored is left alone.
  Tests: `TestFleetUploadedPluginCampaign`, `TestRealtimeCatchesNewLinks`
  (fails on 0.23.41). Real plugins incl. file managers, upload libraries,
  white-label and header/footer plugins: no new finding.
  Not engine work (owner's decision): `captcha.login_gate` is off on
  server1, so wp-login.php shows no human check; brute-force counts only
  failed logins.
  - **Rollback**: `backup-0.23.41`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.23.41: two old false positives found by a real-plugin scan**
  (2026-10-30). Before shipping the ClickFix rules, 34 real plugins and
  libraries close to them (security, CAPTCHA, login limit, 2FA, hide-login,
  cache, maintenance, copy-button, Cloudflare; 9,016 files) were scanned:
  0 from the new rules, 2 from older ones, both fixed in the engine:
  - `PHP.Backdoor.EvalInput` (and the same check for create_function and
    mail): a call name written in a string is no call (iThemes Security
    looks for `'eval('` in the request URI). `assert("eval($_POST..)")`
    is still caught (the outer call).
  - `PHP.Obfuscated.PackedOneLiner`: the long line and the eval must be
    inside PHP tags (`phpRegions`); Duplicator's installer page carrying
    minified jQuery in its HTML is no PHP one-liner. Packed PHP after HTML
    is still caught.
  Test: `TestFleetStringsAndHTMLAreNoCode` (fails on 0.23.40's engine).
  Test runs: `go test -p 1 ./...` (core's firewall tests share the host's
  iptables sets with other packages run at the same time).
  - **Rollback**: `backup-0.23.40`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.23.40: the ClickFix kit (fake Cloudflare human check)**
  (2026-10-30). server1 and server100: 365 fake plugin folders, 1,986
  files, one finding (its .user.ini). The kit shows logged-out visitors a
  Cloudflare look-alike that copies a command (PowerShell, msiexec, or
  `net use` of a WebDAV share) to the clipboard and tells them to press
  Windows+R (or Win+X, I) and Ctrl+V: the visitor runs the malware. New
  rules (`scanner/clickfix.go`, own rules built from how it works):
  - `Phishing.ClickFix.FakeVerification` (.php/.html/.js, mu-plugins too):
    a clipboard write, a Ctrl+V step, a Run box/PowerShell/terminal step and
    a human-check lure ("not a robot", "verify you are human", "Ray ID")
    together, tags removed first (steps are written `<b>Ctrl</b> + <b>V</b>`).
    A how-to with a copy button has no lure; a page with a CAPTCHA and a
    copy-coupon button has no paste step.
  - `Phishing.ClickFix.FakeClearance`: site code writing Cloudflare's own
    `cf_clearance` cookie (document.cookie / setcookie); reading it (cache
    plugins) is no finding.
  - `PHP.Backdoor.DNSTXTDeadDrop`: a TXT record of a fixed domain sent to
    any visitor (wp_ajax_nopriv_); lookups of a visitor's domain and
    admin-only checks are no finding.
  - `PHP.Backdoor.HiddenAdmin`: an administrator made or its password written
    into the users table (a hash in the file), hidden from the user list or
    counts. Temporary-login plugins (no hiding) and hide-user plugins (make
    no user) are no finding.
  - `PHP.Backdoor.LoginLockdown`: authenticate filter + password reset off +
    every REST login refused. No "uses a setting" exception (an attacker
    would add one call); a login policy never refuses REST to everyone.
  - `Htaccess.Hacked.CaptchaRedirect`: a catch-all redirect (home page, all
    pages or static files) to a captcha/challenge/cloudflare page with no
    cookie condition. In a WordPress root the cleaner drops these rules and
    the rules whose conditions name that page, keeps the rest, adds
    WordPress's rules. A maintenance page or a cookie-gated bot check is
    no finding.
  - `PHP.Dropper.HiddenPayload`: a hidden file of only base64 of deflated
    PHP (eval/base64_decode inside); `PHP.SEOSpam.RemoteDoorway`: a loader
    asking its host what to show, with the visitor's URI and a bot flag.
  Test: `TestFleetClickFixKit`. Evidence copies: 19 of 35 caught (the rest
  are images, CSS, overlay markup and a header-only plugin.php); real
  plugin corpora and WordPress core 0; evidence pack 36/101 unchanged; scan
  time unchanged. Not done: an alert for new administrator accounts (the
  agent does not read site databases).
  - **Rollback**: `backup-0.23.39`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
- **Release 0.23.39: a packer slipped past 0.23.35's escape rule; a
  Telegram phishing page** (2026-10-29). The fleet review of quarantined
  files ("findings.recheck" on every server, each "no longer flagged" file
  looked at before restoring) found two holes:
  - `PHP.Obfuscated.CharEncoded` counted escape *runs* (five needed) since
    0.23.35; a packer that puts its whole hex-escaped payload in one string
    (goto flow, openssl_decrypt; business100 ajokaorg recommend.php) is one
    run. It now counts the escapes in runs that decode to text (40 needed);
    Wordfence's binary mask table and phpstan's byte ranges still count 0.
  - `Phishing.KitPage` for .php and .html: a page that reports visitors to
    api.telegram.org/bot and has a form asking for a one-time code, a
    password or a card, outside plugin, theme and vendor folders (a SumUp
    kit in wp-admin/sumup/web/, which the old mailer rule had flagged and
    a later fix let go).
  Restored after a look at each: Vafpress copies, Wordfence, phpstan,
  ForceUTF8 Encoding.php, Unyson, LayerSlider, EWWW binaries, phars,
  cPanel php.ini files, Really Simple Security, site contact forms. Kept:
  the SumUp kit and recommend.php. Rule for the review: a recheck verdict is
  the engine's opinion; a file that is no known library is opened first.
  - **Rollback**: `backup-0.23.38`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.38: inert PHP is really inert** (2026-10-29). A review of
  0.23.37's exceptions for abuse: a hidden "<?php return require 'x';"
  counted as inert (a string table) and escaped the planted-PHP rules. An
  inert file now has no include/require/eval, no `new`, no static call,
  no heredoc. Remaining, accepted trade-offs of 0.23.37 (other rules still
  see such files): readable goto labels, readable $GLOBALS names, a
  *whitelist* function of the file's own, an unanchored .htaccess lock
  without the kits' extension list.
  - **Rollback**: `backup-0.23.37`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.37: libraries quarantined by server1's full scan 62**
  (2026-10-29). Scan 62 (43.7 million files, 3,236 findings) found real
  infections (7 phishing collectors and kits, 28 casino/footer spam files,
  213 obfuscated loaders and fake plugins, Tiny File Manager and GSocket
  shells, UPX-packed "wpbooster" ELF files, 2,600+ kit .htaccess locks)
  and quarantined official code. 114 files were restored (owner's
  approval). Engine fixes, each with its abuse case kept caught
  (`TestFleetLibrariesOfScan62`, `TestFleetAppHtaccessLock`):
  - `Htaccess.Hacked.PHPLock`: a lock without the kits' extension list
    that allows names by ending (phpList admin/.htaccess) is no finding;
    the kits' locks (py|exe, mixed-case PHP, .suspected, ^(…)$ names) stay.
  - `PHP.Obfuscated.CharEncoded`: escape runs count only when they decode
    to text (Wordfence wf-waf utils.php's IPv6 mask table is binary).
  - `PHP.Backdoor.DynamicCall`: a request-named function checked by the
    file's own *whitelist*/*allowed* function first (Vafpress in JNews and
    Rehub). in_array() is no check (the backdoor writes the list).
  - `PHP.Backdoor.FileDropper`: not in a large (>20 KB) admin file that
    checks nonces or capabilities and uses no chr() or hard decoder
    (LayerSlider actions.php).
  - `PHP.Backdoor.PregReplaceEval`: /e with a fixed replacement that wraps
    the match in code (SquirrelMail charsets, SitePad); a replacement that
    is the match itself, names a command or decoder, or a subject from the
    request (also through a variable) stays.
  - `PHP.Backdoor.CommandInjection`: $_SERVER['argv'/'argc'] is no web
    input (Symfony build and test scripts).
  - `PHP.Obfuscated.GotoFlow`: not when 90% of the labels are long words
    (generated routers).
  - `PHP.Backdoor.GlobalsDispatch`: not when every $GLOBALS call uses a
    readable name (phpxmlrpc's saved error handler).
  - `PHP.Obfuscated.CharDecoder` without eval: the chr()/xor build must be
    within 1,500 bytes of the variable call (Unyson's random string).
  - `PHP.Obfuscated.HaltCompilerPayload`: extensionless phars (phpunit
    tools/composer, ~/composer) are opened like .phar files.
  - Planted PHP: inert files (first statement exit/die, or only `return`
    of a string table: LiteSpeed Cache .litespeed_conf.php, PicoFeed
    rules) and the exact names .stubs.php, .sami.php, .psysh.php (prefix
    matching would have let .stubs_<hex>.php through).
  - CodeInNonScript: a weak sign in a Perl/Python/shell program (#! line)
    is no finding (SquirrelMail conf.pl); a malicious verdict stays.
  - `PHP.Config.AutoPrepend`: Really Simple Security's
    wp-content/advanced-headers.php with its marker.
  - Weak JS signs inside node_modules (js-beautify's unpackers).
  Left quarantined for a look: GoDaddy's mu-plugin system-plugin-worker
  functions.php (EvalDecodedPayload, AI unsure), Adminer as
  wp-includes/check_db.php (planted), rehub-framework.zip.
  Note: server1 quarantines suspicious files too, so a "suspicious"
  downgrade is no fix there; a legit case must be no finding.
  - **Rollback**: `backup-0.23.36`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.36: the kit rules no longer slow scans down** (2026-10-28).
  server1's full scan ran at about 280 files a second (595 before
  0.23.34). The agent's profile showed regexp's NFA (`machine.add`,
  `unicode.SimpleFold`) on top: 0.23.34's kit rules ran their
  case-insensitive regular expressions on every PHP and HTML file. A
  timing over 3,000 plugin and core files plus 200 large HTML pages: the
  kit rules took 13.6 s of a 27 s analysis, the place rules 4.7 s. Each
  rule now first checks its plain words (bytes.Contains: "t.me/s/",
  "all_plugins", "/api/links", the string-piece and `$var_` counts, a
  Telegram word, a casino word, a ".php" a page names) on one pooled
  lowercase copy; the regular expressions run only on files that have
  them. Now 0.8 s and 0.03 s, same detections (evidence 36 of 101, the
  plugin and core corpus clean, all tests).
  Keep it so: a new content rule starts with a plain-word check.
  - **Rollback**: `backup-0.23.35`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.35: false positives of server1's full scan** (2026-10-28).
  Full scan 59 found 9,793 files after 8 of 1,498 accounts; the owner had
  it stopped. All were wrong:
  - 9,790 `PHP.Planted.HiddenFile` (suspicious; the signature had paused
    itself): macOS AppleDouble files (`__MACOSX/…/._Kernel.php`, magic
    00 05 16 07, metadata of a Mac archive, no code) and PsySH's
    `.psysh.php` fixture. The planted-PHP rules skip AppleDouble content;
    `.psysh` joins the developer dotfiles. A "._" name with real PHP in it
    is still found.
  - `PHP.Loader.HiddenInclude` (quarantined) on PHP-CS-Fixer's
    `.php-cs-fixer.tests.php` and `.dist.php` (they require
    `.php-cs-fixer.common.php`): an include of a developer dotfile is no
    hidden include.
  - `PHP.Obfuscated.CharEncoded` (quarantined) on phpstan's
    ConstExprStringNode.php: a regex of byte ranges (`[\x00-\x08]`) and an
    `assert(strlen(…) === 1)`. Hex and octal escapes now need five runs of
    four or more ("\x65\x76\x61\x6c"), which encoded code has and byte
    ranges do not.
  The three quarantined files were restored. Test:
  `TestFleetMacMetadataAndDevFiles` (fails on 0.23.34, five cases). After
  the update: `findings.recheck_apply` on server1 clears the stale
  findings, then the full scan can run again.
  - **Rollback**: `backup-0.23.34`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.34: phishing kits, casino spam, fake plugins** (2026-10-28).
  server1's evidence pack (101 files: a Mercantil bank phishing kit, casino
  SEO doorways, EtherHiding fake plugins, "woocommerce_inputs" loaders, a
  C2 address file) had no finding. New rules in `scanner/kits.go`, all our
  own, built from how each family works:
  - `PHP.Obfuscated.SplitStrings`: 40+ string pieces ('wp'.'_fo') with
    add_action (the fake plugins' inc/class-handler.php);
  - `PHP.Obfuscated.HashNames`: 20+ md5-named identifiers, or 10+ with a
    network fetch (woocommerce-load.php);
  - `PHP.Backdoor.TelegramDeadDrop`: reads a t.me/s/ channel page and adds
    users or includes code; `PHP.Backdoor.HiddenPluginLoader`: hides itself
    from the plugin list and its action links, downloads, writes and
    includes code (the older woocommerce_inputs.php);
  - `PHP.SEOSpam.RemoteFooterLinks`: /api/links fetched without TLS checks
    and printed in the footer (fhelpers.php);
  - `Phishing.Collector.Telegram`: Telegram bot settings, the visitor's
    address or browser and three kinds of secret with a card or bank login
    among them (a one-time-code plugin sending by Telegram stays clean);
    `Phishing.KitPage`: an HTML page naming a sibling script that is such a
    collector;
  - `HTML.SEOSpam.HiddenGambling`: an element hidden by its own style
    (clip, 1px, far off screen; not display:none, which themes use for
    menus) holding 15+ links and 10+ casino terms;
    `PHP.SEOSpam.HiddenGamblingPrinter`: a mu-plugin printing such a
    sibling .html in the footer; `HTML.SEOSpam.GamblingDoorway`: a static
    .html named for casino offers, outside wp-content, copying the site's
    WordPress page (5+ wp-content references) with 40+ casino terms;
  - `Dropper.Base64URL`: an extensionless 32-hex-named file holding only a
    base64 http(s) URL.
  Evidence: 36 of 101 files now found (every kit, plugin and loader's
  working file; the rest are images, CSS, readme and data). Elementor,
  Yoast, LiteSpeed Cache, MainWP Child, Contact Form 7, WP Mail SMTP,
  the Stripe gateway, the WordPress importer and WordPress core: no
  finding. Test: `TestFleetPhishingCasinoAndLoaders` (inert fixtures and
  look-alikes).
  - **Rollback**: `backup-0.23.33`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.33: fixes from three server audits** (2026-10-27). The
  owner's server assistant audited business200, server1 and business500.
  Checked against the code; fixed what was right:
  - wp-cli ran as the site owner without a HOME (the agent's environment
    under systemd): "mkdir '/.wp-cli/cache/': Permission denied", 326
    failed updates on business500. `wpEnv` (cms) sets the owner's HOME
    (or HOME=/tmp and no cache). Test `TestWPCLIHome`.
  - The CMS scan ran a new site's automatic updates before saving it, and
    wp-cli looks the owner up in the list: "WordPress site not found (run
    a CMS scan first)", 1,073 times on business500. Saved first now. Test
    `TestNewSiteSavedBeforeUpdates`.
  - CAPTCHA server: client errors ("http2: server: error reading preface
    from client …", GOAWAY, connection errors) are counted
    (`ClientErrors`), not logged (server1: 122,251 lines, 95 MB).
    Test `TestCaptchaClientNoiseNotLogged`.
  - WAF events kept 35 days (`wafEventDays`), not with the logs' 60:
    business500 had 4 million rows in 18 days (1.1 GB database).
  - Not right (left as is): firewall "dead chains" (XPGUARD_CTRY is jumped
    to only with blocked countries; XPGUARD_EXEMPT holds the port filter's
    rules, off; banned addresses' web traffic is reset/redirected before
    XPGUARD_TBAN); AI restore loop (the AI has not restored files since
    0.23.8; the log lines were older); "no log rotation" (the agent
    rotates agent.log itself); exit status 3 (the self-update's restart,
    must stay a failure for Restart=on-failure); the WooCommerce
    "LanguageFactory.php" (a 631-byte PHP in a JS asset folder that no
    plugin checksum matches: a dropper); localhost SQLi probe returning
    200 (the server's own addresses are not inspected); CAPTCHA ports
    listening publicly (the firewall redirects visitors to them);
    PK in ignored_countries (owner's policy).
  - Open, owner to decide: reinfection escalation (a file coming back
    1,000+ times; auto-suspend is off), restoring an official plugin
    file the scanner quarantined (Elementor on 2 business500 sites),
    CRS anomaly threshold 10 at level normal, `max_file_size_mb` 10 (PHP
    over it is read at both ends already).
  - **Rollback**: `backup-0.23.32`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.32: same-site relaxations without macros (LiteSpeed)**
  (2026-10-27). joomlashares.com (business600, joomlash, behind
  Cloudflare): Joomla Global Configuration saves were still refused on
  2026-10-26 15:57-16:08 UTC, after 0.23.28 (930120 + 932160, and 941100
  + 941160; score 10). The remaining LiteSpeed-only link in the admin-area
  lift (7700058) was the Host comparison `TX:1 "@streq
  %{REQUEST_HEADERS.Host}"`; the session lift (7700044) used the same kind
  (`%{tx.xg_host}`). Inferred, not proven on a LiteSpeed engine.
  - `adminAreaSetup`: Referer in the admin area (no capture), same site from
    the browser's `Sec-Fetch-Site: same-origin` (already required).
  - `sessionSetup`: a second rule `IDSessionSite+1000` (7701044):
    `Sec-Fetch-Site: same-origin` + a session cookie read from the Cookie
    header, not WordPress or WooCommerce, not a /wp- path; same threshold
    30 and the same XSS cap afterwards.
  - The customer asked for the WAF off on /administrator/ and for the
    origin to accept only Cloudflare: not done (owner's decision; the
    server's address is shared by every account, so a firewall rule cannot
    do it per account; per site it is `.htaccess` / LiteSpeed access
    control). The site gets daily front-end attacks the WAF blocks.
  - Tests: `TestAdminAreaReadsCookieHeader` (no macro, session rule);
    Apache `TestAdminAreaSavesWithoutRuleRemoval` (Global Configuration).
  - **Rollback**: `backup-0.23.31`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.31: hidden and logs-folder PHP; quarantine kept a week**
  (2026-10-26).
  - business100: the owner's server assistant (another tool, root shell)
    cleaned two SEO doorway farms (sahibsul, bashopco) and 9 infected
    accounts, moving files to /root/malware-quarantine-serverwide-20261026
    (not xPGuard's quarantine). xPGuard had no finding for sahibsul or
    bashopco. From its report: dormant copies `.sys_<hex>.php`,
    `.sess_<hex>.php`, `.tmp_<hex>.php`, `.cache_<hex>.php` (mode 000),
    restore scripts in `~/logs/` (cache_gc.php, restore_config.php), a
    `.sitemap_indo.php` generator, `/* SC_WC */` in wp-config.php, rogue
    admins (bot@local.invalid …) and casino spam posts. Its spam-post
    cleanup trashed legit posts too (restored by it).
  - `plantedByName` (scanner/planted.go, PHP only, after known-good and
    hash checks): PHP in `~/logs/` → `PHP.Planted.InLogsFolder` (virus);
    hidden PHP named by random hex → `PHP.Planted.HiddenRandomName`
    (virus); hidden PHP with mode 000 → `PHP.Planted.HiddenDormant`
    (virus); other hidden PHP → `PHP.Planted.HiddenFile` (suspicious, the
    AI looks). Developer dotfiles (`.php*`, `.rector*`, `.phan*`,
    `.psalm*`) and `.env*.php` stay alone. The mode is read only for
    hidden files. Recheck keeps `PHP.Planted.*`.
  - Not covered yet (need content or the database): the SC_WC wp-config
    injection, rogue admin accounts, spam posts (research items M3, I4).
  - Quarantine retention (owner): `scanner.quarantine_days`, default 7,
    separate from `keep_days` (logs, 60). `pruneOld` deletes quarantined
    files (and kept originals of trimmed/cleaned files) older than that,
    20,000 per 6-hour round; on a server's first round after the update it
    starts a one-week grace (kv `quarantine_week_since`), so files already
    in quarantine can still be restored that week. Settings » Virus
    Scanner: "Keep quarantined files for".
  - Tests: `TestFleetHiddenAndLogsPHP` (fleetfp_test.go, inert fixtures),
    core `TestQuarantineKeptAWeek`.
  - **Rollback**: `backup-0.23.30`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
    Files the retention already deleted do not come back.

- **Release 0.23.30: LiteSpeed restarts at least 90 s apart, also after an
  agent update** (2026-10-26). Owner: after recent updates some LiteSpeed
  servers filled with "nobody" processes and the load went up until they
  were killed. An update restarts the agent; `lastReload` started at zero,
  so the reload gaps did not apply, and in the first minute the WAF start
  (`Run` → Apply), the portal's rule sync (wafsync → Apply) and the CAPTCHA
  settings (central → Apply) could each run `lswsctrl restart`. A graceful
  LiteSpeed restart keeps the old processes until their connections end:
  several restarts close together stack generations of them. Not seen in
  logs (no restart log in the portal); inferred from the code.
  - `install` (waf/install.go): LiteSpeed restarts are at least
    `LiteSpeedMinGap` (90 s) apart; a sooner one is scheduled once
    (`deferred`, everything meanwhile in one restart); a change someone
    made (`modeNow`) waits up to `LiteSpeedNowWait` (45 s), else is
    scheduled; a solved CAPTCHA keeps its own 30 s gap. The last reload is
    kept in kv `waf_last_reload` across agent restarts (`loadLastReload`).
    Apache (graceful re-read) is unchanged.
  - Test: `TestLiteSpeedRestartsSpacedOut` (reloadgap_test.go).
  - Not changed: on servers with many CAPTCHA solves LiteSpeed still
    restarts up to every 30 s for passes; watch for load there.
  - **Rollback**: `backup-0.23.29`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.29: wp-cli without the site's plugins; CMS checks at night,
  slowly** (2026-10-26).
  - brandaville.com (business100, brandavi): every plugin update from CMS
    Threat Alerts failed with the site's own fatal error (Elementor Pro
    2.7.2 with Elementor 4.1.4; the site shows "There has been a critical
    error"; Elementor had no known vulnerability, so xPGuard did not
    update it). `wpArgv` (cms/cms.go) runs wp-cli with `--skip-plugins
    --skip-themes` for every command (updates, core download,
    deactivation), so a broken site can still be updated.
  - Owner's request: CMS checks only at night, very slow. `nightHour` is
    2:00-6:00 (scan schedule time zone, Asia/Karachi on the fleet).
    "Scan now" (agent `cms.scan`) queues a full scan for the next night
    (`RequestScan`, kv `cms_scan_requested`; button "Scan tonight",
    `cms.status.scan_requested`). The daily `VulnPass` runs in the night
    window too. Between sites `slowDown`: wait for load per CPU < 0.7 (up
    to 2 min), then 2 s. A single update from the portal refreshes that
    site only (`RefreshSite`), no longer a full scan. Bulk updates and
    single updates still run when asked.
  - Seen: brandaville.com has 4 foreign PHP files in core
    (`wp-admin/includes/class-wp-page-thXuMD.php`, `.../medias.php`,
    `wp-includes/customize/class-wp-customize-filters-setting.php`,
    `wp-includes/wp-class.php`) without a scanner finding; content not
    seen. Owner informed.
  - Tests: cms `TestWPCLISkipsSiteCode`, `TestCMSScanAtNight`.
  - **Rollback**: `backup-0.23.28`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.28: Joomla (and other) admin saves on LiteSpeed**
  (2026-10-26). joomlashare.ir (business600, LiteSpeed, account joomlash):
  jDownloads, RSMembership and File Explorer saves in /administrator/
  refused by CRS 949110 (score 10-30: 941100, 932230/932250, 932120,
  933120 …) from 2026-10-19 to 10-25, the owner's address even banned
  ("15 WAF blocked"). The admin-area lift (7700058, `adminAreaSetup`) and
  the admin-panel exclusion (7700018) tested `&REQUEST_COOKIES "@gt 0"`;
  LiteSpeed's engine does not fill the cookie collections reliably (as
  with WordPress login cookies, 0.22.6), so they never matched there; the
  Apache test (TestAdminAreaSavesWithoutRuleRemoval) passed all along.
  Both now read the Cookie header (`[^\s;=]+=[^\s;]`). Not verified on a
  LiteSpeed engine here: confirm with the customer's next save.
  - The same site gets front-end code-injection attempts daily
    (`{source}<?= … ?>{/source}` in feed URLs, dropping 41091a89b87e.php):
    blocked; the customer was told not to switch the WAF off.
  - business600's `waf.whitelist_domains` lists the customer's domains:
    that only removes xPGuard's own rules (7700003-7709999), not the CRS.
  - Tests: `TestAdminAreaReadsCookieHeader`; Apache
    `TestAdminAreaSavesWithoutRuleRemoval` (jDownloads save, empty cookie,
    front-end injection).
  - **Rollback**: `backup-0.23.27`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.27: PHP planted in WordPress core folders** (2026-10-26).
  `/home/nutrishoppk/Old-files hmy` (business200 websoulhost) had
  `worksec.php` in 42 core folders (CMS core check: "unknown"); a path
  scan (id 180, 39,199 files) found nothing: each copy's content passed the
  content rules. Content not looked at (no finding to read it from).
  - `scanner/planted.go` `plantedInCore` (in `contentVerdict`, after the
    known-good and hash checks, PHP only): WordPress keeps no PHP in
    `wp-admin/css`, `wp-admin/images`, `wp-includes/css`,
    `wp-includes/images` (`coreAssetDirs`; not `wp-includes/fonts`, which
    has PHP since 6.5). A name there with copies in 3 or more other core
    folders (`coreDirs`) is `PHP.Planted.WordPressCoreSpray` (virus), every
    copy in every core folder; one there alone is
    `PHP.Planted.WordPressCoreAssets` (suspicious, the AI looks). Only a
    WordPress site (wp-includes/version.php). Files elsewhere in core cost 4
    lookups. Droppers found are remembered 24 h (`sprayed`) so the last
    copies stay caught while the others are quarantined. Recheck keeps
    `PHP.Planted.*` (judged by place, not content).
  - Test: `TestFleetPlantedInWordPressCore` (fleetfp_test.go, inert fixture).
  - After the agent update: a path scan of that folder.
  - **Rollback**: `backup-0.23.26`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.26: automatic updates of vulnerable WordPress that work;
  bulk updates** (2026-10-26).
  - Checked on business200 websoulhost (auto update on, CVSS above 6,
    7 days): 1,567 of 1,620 sites outdated and almost nothing updated.
    Many new vulnerabilities have no CVSS score in WPVulnerability (0):
    never "above 6". A critical one waited 7 days (attacks start within
    hours). Core was never updated (WP2Shell). The CMS check ran every
    3 days at night only.
  - `autoUpdateDue` (cms/vulns.go): a vulnerability without a score counts;
    CVSS >= 9 (`autoUpdateNowCVSS`) skips the waiting days; otherwise the
    settings as before. Core: `wp core update --minor` (the branch's
    security release) when core has known vulnerabilities and a newer
    release exists. `UpdateArgs`: a plugin or theme a whole major version
    behind goes to the highest fixed release of its own branch
    (`--version=`) when every hole is fixed there, else the newest.
    "WordPress is up to date" counts as no update. wp-cli also takes
    `--minor` and `--all`.
  - `VulnPass` (cms/cms.go): every 20 hours between full scans, each stored
    WordPress site's plugins, themes and version are re-read, looked up and
    the automatic updates applied (`refresh`); core file and database
    results of the last full scan stay. Not during a scan.
  - Bulk update (cms/bulk.go, agent `cms.bulk_update`, admin): the
    selected sites, one account's (`account`, also a cms.sites filter) or
    all; mode "vulnerable" (what has a known hole, core to its security
    release) or "outdated" (`plugin/theme update --all`, `core update
    --minor`). In the background, one at a time, progress in
    `cms.status.bulk`; no scan meanwhile. "Never patched automatically"
    accounts are left out unless selected one by one. CMS Threat Alerts:
    risk and account filters, checkboxes, the bulk bar with progress.
  - Seen on the way: `/home/nutrishoppk/Old-files hmy` has `worksec.php` in
    42 WordPress core folders (core check "unknown"), with no scanner
    finding. See 0.23.27.
  - Tests: cms `TestAutoUpdateDue`, `TestVulnPass`, `TestBulkUpdate`.
  - **Rollback**: `backup-0.23.25`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.25: shared egress networks stay off the fleet IPDB**
  (2026-10-25, owner's decision). One iCloud Private Relay or Meta address
  carries thousands of people; one person's mistakes (0.23.24's false
  bans of 104.29.x) put it on every server's list, and every Safari
  visitor met the CAPTCHA everywhere.
  - `ipdb/shared.ts` (`SharedEgress`): Apple's published relay ranges
    (`mask-api.icloud.com/egress-ip-ranges.csv`, downloaded daily by
    `refreshRelay`, kept in table `ipdb_relay`, migration 032; a download
    under 1,000 ranges or a failed one keeps the saved list) and Meta's
    networks (`META_RANGES`: 57.141.0.0/16, 2a03:2880::/29). `doRebuild`
    leaves entries inside them out of the distributed list unless the
    operator listed them by hand. Cloudflare's own ranges are not taken
    whole: WARP, a free VPN, shares them and stays listable. Check IP shows
    `shared`. Bans on the server itself are unchanged.
  - The CAPTCHA's `SHARED_EGRESS` (allowances, same network) is unchanged.
  - The portal must reach mask-api.icloud.com (until then only Meta's
    ranges are left out; the log says "private relay list download failed").
  - Tests: `ipdb-shared.test.ts`.
  - **Rollback**: `backup-0.23.24` (the `ipdb_relay` table stays, unused);
    agents unchanged.

- **Release 0.23.24: the WordPress admin folder is no login page; login
  attack mode from 2 addresses** (2026-10-25).
  - Owner's test 07:58-08:02 PKT on primescopeusa.com (business200
    websoulhost) through Firefox's VPN: 10 failed logins from
    63.245.217.85 (banned at the 10th), then the VPN moved to
    63.245.217.24 for 5 more; no CAPTCHA. Site attack mode needed 3
    addresses; the 3-failures suspect list only reaches the WAF at the
    10-minute refresh (a reload restarts LiteSpeed, so it stays so).
    `loginAttackAddrs` is 2 now (still 10 failed logins in 15 minutes).
  - Found on the same server: business200 lists `/wp-admin` as a
    protected login URL. Rule 7700405 counted every POST of a logged-in
    admin's screens (`/wp-admin/admin-ajax.php`: heartbeat, autosave,
    200 answers) as a failed login: primescopeusa.com's own admin on
    iCloud Private Relay (104.29.x) was banned again and again ("10 failed
    protected URL logins"), refused by the CAPTCHA ("attacked after solving
    the CAPTCHA and stays banned") and the site went into login attack mode
    from its admin's heartbeats; fleet reports put those relay addresses on
    the IPDB. `waf.LoginPages` drops `/wp-admin` (and below) from the
    protected URLs in `Render` (counter 7700405, gates, the IPDB POST
    exemption) and `siteLoginURLs` uses it. wp-login.php keeps its own rule.
  - Tests: waf `TestWPAdminIsNoLoginPage`, core `TestLoginAttackSites`
    (two VPN addresses).
  - Relay addresses listed on the IPDB from those false bans: see 0.23.25.
  - **Rollback**: `backup-0.23.23`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.23: VPN and cloud visitors can solve the CAPTCHA**
  (2026-10-25). Through Firefox's built-in VPN the owner reached the
  hostname page and got "This check cannot be completed from a hosting or
  cloud network". The VPN reaches the website over IPv4 (45.58.241.39)
  and the portal over IPv6, both cloud addresses (AbuseIPDB usage type),
  so the 0.23.12 farm rule refused it ("solved from a hosting network for
  another address"); ALTCHA from a hosting address was refused too. Every
  VPN and agent-browser visitor (Muse and the like) was shut out.
  - Both refusals are gone. A check solved from a hosting network (for
    another address, or by ALTCHA; privacy relays still count as people)
    gives a pass of at most `ALTCHA_FALLBACK_MINUTES` (60), recorded as
    "from a hosting network (VPN or cloud): a pass for an hour", and at
    most `HOSTING_PASSES_PER_DAY` (4) such passes per target address a
    day ("hosting-network passes for this address used up today" after
    that). Turnstile solved for its own address is unchanged.
  - What still stops abuse: a pass only lifts the IPDB/redirect (0.23.15,
    no whitelist), the next attack bans the address and ends the pass,
    solving again does not lift that ban (`PassRefused`), the human tick
    for ALTCHA, 3 other addresses an hour per solver, ALTCHA daily limits.
  - Tests: server `captcha.test.ts` "lets VPN and cloud visitors pass for
    a short time…" and "lets a VPN solve for its other address…".
  - **Rollback**: `backup-0.23.22`; agents unchanged (portal only).

- **Release 0.23.22: hostname CAPTCHA "Not Secure" for banned visitors**
  (2026-10-25). After ~10 fake logins through Firefox's VPN the owner was
  banned (WAF ban, threshold 10) and sent to
  `https://business200.websoulhostservers.com/xpguard-check/…&k=fw…`;
  Firefox warned "Not Secure". In Chrome, from the owner's own (not
  banned) address, the same page was fine. A banned address's 80/443
  traffic is redirected by the firewall to the agent's CAPTCHA server,
  and the hostname is on the same address: the agent served the page
  with its self-signed fallback (cPanel keeps the hostname's certificate
  with the service certificates, not in apache_tls). The self-test only
  checked the web server.
  - `CertStore` now tries cPanel's service certificates for a name it has
    no website certificate for (`ServiceCerts`: cpanel.pem, mycpanel.pem
    (+ .key, + .cabundle), exim, dovecot, pure-ftpd; valid now and for the
    name).
  - `CheckOwnTLS` tests the agent's CAPTCHA HTTPS port for the hostname;
    only when it passes does the firewall's redirect (IPDB, bans) use the
    hostname page (`central.hostFW`, `Captcha.HostPage` =
    `hostPageFWURL`); otherwise those visitors go to the portal address.
    Login-page suspects (WAF) are unaffected: their traffic reaches the
    web server.
  - Test button and waf.status show the firewall part (`firewall_ok` /
    `firewall_error`).
  - Tests: captcha `TestHostnameServiceCertificate` (cert + key file,
    combined file, other names, own-port check, self-signed refused); core
    `TestHostnameModeFallsBack` (no firewall redirect to the hostname
    without a valid certificate).
  - **Rollback**: `backup-0.23.21`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.21: login attack mode holds, and starts within seconds**
  (2026-10-25). The owner set business200 to the hostname CAPTCHA (its
  setting arrived: `central_mode` "hostname") and tried fake logins on
  websoulhost.com through Firefox's built-in VPN: 16 attempts from 4
  addresses (45.58.241.5/.105/.94/.104) in 73 seconds, no CAPTCHA. The
  site had been in login attack mode minutes before, but the mode only
  counted the last 30 minutes (15 failures, 3 addresses): it dropped as
  the earlier attempts aged out, and coming back took the minute check
  plus a reload, after the burst was over. So the hostname page was never
  reached (no gate), which looked like "hostname mode does not work".
  - Now: 10 failed logins from 3 addresses in 15 minutes start it, and it
    holds for an hour after the threshold was last met (`loginAttackHold`,
    `central.attackLast`, in memory). Every failed login read from the
    logs nudges `centralLoop` (`WAF.OnLoginFailed` → `onLoginFailed` →
    `central.kick`), which checks within seconds (at most every 10 s)
    and reloads at once when a site comes under attack.
  - Attack mode never gates `/wp-admin` (business200 lists it in
    `waf.login_urls`): admin-ajax.php and admin-post.php serve every
    visitor's carts, forms and searches.
  - Visibility: waf.status `captcha_hostname` {wanted, url in use, error};
    connector action `captcha.hostcheck` (operator); the CAPTCHA page's
    Test says whether the hostname page is in use now.
  - Tests: core `TestLoginAttackSites` (hold, end of hold, the Firefox
    burst, /wp-admin), `TestFailedLoginKicksCheck`; waf
    `TestFailedLoginNotifies`; race detector on core and waf.
  - **Rollback**: `backup-0.23.20`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.20: failed logins and CAPTCHA redirects findable in the
  WAF log** (2026-10-25). The owner made 10+ fake logins on
  websoulhost.com, was sent to the CAPTCHA (the site was in login attack
  mode), and found none of it in the WAF log. All 28 attempts were
  recorded (7700401, 45.58.238.97 ×10, 149.143.161.47 ×8, 46.229.243.220
  ×10, category `login`), but the WAF Logs page opens on "Blocked attacks"
  (category `waf`) and searched only there; the CAPTCHA redirect itself
  was never stored (gate rules 7700900-7700919 were skipped).
  - WAF page: a search now looks through all entries ("All events") with a
    label per row (blocked attack, failed login, sent to the CAPTCHA, bot);
    failed logins show "failed login", not "logged"; new view "Sent to the
    CAPTCHA".
  - Agent: a gate redirect is recorded once per address and site in 30
    minutes (`NoteCaptchaSent` returns whether it is the first,
    `captchaLogGap`), category `captcha`, action "Sent to the CAPTCHA"
    (the non-browser 403 keeps its action). Not in the blocked counts,
    never toward a ban. The log handling moved out of the tailLogs closure
    into `Manager.handleEvent` (state in `tailState`) so it can be tested.
  - Test: waf `TestCaptchaRedirectLogged`.
  - **Rollback**: `backup-0.23.19`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.19: the CAPTCHA on the server hostname (no port)**
  (2026-10-25). The owner finds site mode's port 7743 useless (networks,
  VPNs and Cloudflare refuse it) and websites' own addresses unreliable
  (caches, proxies). Third place for the check, per server (CAPTCHA page »
  Where the check opens » "Server hostname (no port)", config
  `hostname_servers`, mode `hostname`):
  - The agent writes a static page to the hostname's document root
    (`/var/www/html/xpguard-check/index.html`, captcha/hostpage.go). The
    WAF sends suspects to `https://<hostname>/xpguard-check/?s=…&ip=…&h=…&u=…`
    (rule redirect when `Central.HostPage` is set; rule 7700068 turns the
    engine off for that path on the hostname); the firewall's own redirect
    (IPDB, bans) too, and the agent's CAPTCHA server serves the page itself
    for those visitors (their connections to the hostname come to it).
  - The page frames the portal's check with the link's parameters plus
    `fh=1`. The portal allows only `https://<hostname from the server's
    record>` to frame it (frame-ancestors), passes the address through the
    pass list (`captcha.pass`, like the portal address), records via
    `hostname`, and tells the page (`postMessage({xg:'passed'})` to that
    origin only, `leave()` in page.ts); the page sends the visitor to
    `https://<site><page>` built from its own link (site name and path
    checked), never from the message.
  - **Self-test** (`CheckHostPage`): the hostname resolves to this server,
    port 443 of this machine answers with a certificate valid for the
    hostname, and the page is ours. Every 10 minutes and when the portal
    pushes the setting (`syncHostPage`); only while it passes does the WAF
    use the hostname page, otherwise the portal address (never a broken
    page). Another place chosen removes the page.
  - **Test button** (owner's request): CAPTCHA page » each server » "Test
    hostname" (`POST /api/captcha/hostname-test` → agent
    `captcha.hostcheck`) sets the page up and tests it, shows the error or
    a "Preview the check there" link (`preview=1` framed by the hostname:
    the check works, no one passes).
  - Tests: agent `TestHostPage`, `TestCheckHostPage` (TLS, wrong name,
    wrong page, DNS elsewhere, 404), `TestHostPageForFirewallVisitors`,
    `TestHostPageFixture` (server/test/fixtures/hostpage.html must equal
    the agent's page; `XG_UPDATE_FIXTURES=1` rewrites it),
    `TestHostPageRedirect`, `TestHostPageOnApache`,
    `TestHostnameModeFallsBack`; server captcha "opens on the server
    hostname…", browser "hostname mode: the check on the server hostname,
    then back to the website" (preview and a real pass with the fixture).
  - Not tested here: LiteSpeed and a real cPanel hostname certificate
    (no LiteSpeed or public certificate in the container). Use "Test
    hostname" on one server first.
  - **Rollback**: `backup-0.23.18`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`
    (choose the portal address again first; the static page is removed by
    0.23.19 agents when another place is chosen).

- **Release 0.23.18: where a site-mode check was solved** (2026-10-25).
  The owner saw the servers set to "the website's own address" send
  visitors to the CAPTCHA domain (recaptcha.world). That is the 0.23.11
  design: the WAF sends a site-mode suspect to the portal's page with
  `g=<port>`, which loads `https://<site>:7743/.xpguard/ping.gif` and goes
  on to the gate on the website within 3 seconds, or shows the check on
  the portal when the port does not answer (a website behind Cloudflare, a
  VPN or office network that only opens 80 and 443: the owner tested
  through Browsec all day). The first hop is always the portal ("One
  moment…"). Nothing recorded which way visitors went (gate events are
  not stored, the portal did not tell), so it could not be checked.
  - Now `probePage` adds `pf=t` (no answer in 3 s) or `pf=e` (refused or a
    certificate error) to the fallback; `captcha_events.via` (migration
    031) records `site` (solved in the frame on the website),
    `port-timeout`, `port-refused`, or '' (portal mode). Shown under each
    row of CAPTCHA page » Recent checks; the connector's `captcha_events`
    returns `via` and `where_solved` (per server).
  - Read `where_solved` after a day: mostly `site` = working, the owner's
    fallbacks were the VPN; mostly `port-refused` on a server = its port
    7743 is blocked (host firewall, provider firewall) or the sites are
    behind Cloudflare; `port-timeout` = dropped packets or a slow handshake
    (consider a longer probe).
  - Tests: server captcha (pf links, via recorded), browser "site mode goes
    to the website when its port answers, and records why it did not".
  - **Rollback**: `backup-0.23.17` (the `via` column stays, unused).

- **Release 0.23.17: login attacks from many addresses** (2026-10-25).
  The owner tried 10+ fake WordPress logins on websoulhost.com
  (business200) from Browsec VPN and was never blocked. The logs: 22
  failed logins in 3 minutes, all counted (7700401), but from 6 addresses
  (the VPN changed address every 1-7 attempts: 45.58.242.100,
  45.58.242.10, 45.58.238.93, 45.58.238.19, 149.143.161.99,
  149.143.161.22). The only defence was per address: the WAF bans after
  `waf.bf_threshold` (10) failed logins in `bf_window_minutes` (10), and
  failed logins (action "Logged", rule count) never made an address a
  CAPTCHA suspect (suspects needed 3 refused requests). Botnets rotate the
  same way: business200 had 275 failed logins in 17 minutes, nearly all
  from different addresses.
  - **Site attack mode**: a website with 15+ failed logins (7700401
    WordPress, 7700405 protected URLs; not XML-RPC) from 3+ addresses in
    30 minutes (`loginAttackSites`, core/central.go) gets `Central.Sites`:
    rule 7700067 (`SERVER_NAME` of the site + its login page) marks every
    visitor a suspect, so the central gate sends each browser to the
    CAPTCHA and refuses scripts (403), whatever the address. Gated pages
    (`siteLoginURLs`): the WordPress login and protected URLs, not
    xmlrpc.php or the Joomla/OpenCart admin scripts. Not with the CAPTCHA
    for everyone (`All`). It ends 30 minutes after the attack stops.
    `centralLoop` checks every minute and reloads at once when a site comes
    under attack (`CentralSitesAdded`, file `captcha-sites.txt`); the full
    suspects refresh stays every 10 minutes. The WAF page shows the sites
    (waf.status `login_attack_sites`).
  - **Suspects**: an address with 3 failed logins in the last hour gets the
    CAPTCHA on its next login page visit (refreshed every 10 minutes); the
    ban at 10 stays.
  - Connector `get_settings` returned the agent's whole answer, whose user
    list filled the 60,000-character limit before the settings on big
    servers: it now returns only `settings` and `apply`.
  - Tests: waf `TestSiteAttackRule`, `TestSiteAttackOnApache` (real Apache:
    the attacked site's login page redirects a non-suspect browser and
    refuses a script, its other pages, other sites and a look-alike name do
    not; a pass and the attack's end open it); core `TestLoginAttackSites`
    (the owner's VPN pattern, a single address, a few people mistyping,
    www/port names, XML-RPC and old events, the 3-failure suspects).
  - **Rollback**: `backup-0.23.16`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.16: the CAPTCHA at once when an address is listed
  during a visit** (2026-10-25). The owner tested from a Browsec VPN
  address (37.203.35.18) on yamalcustompackaging.co.uk (business200):
  `/wp-admin.php` 7 times got WAF 403s (7700311 fake core file, a
  scanner-only rule: right; the real path is `/wp-admin/`), those 403s
  went to the portal as probe reports (`IPDBProbeReports`, 3 list an
  address), the portal listed it and pushed the list (minutes later),
  and then the page would not load for a while before the CAPTCHA came.
  - **Cause**: the browser's keep-alive connection to 443 was opened
    before the listing. The nat redirect only sees new connections, and
    the input chain dropped that connection's packets silently: the page
    hung until the browser gave up on it.
  - **Fix**: before the IPDB and ban drops, web connections (80, 443) of
    listed (not passed) or banned addresses are reset when the CAPTCHA
    redirect is on (`reject with tcp reset` / `REJECT --reject-with
    tcp-reset`, comments xg-ipdb / xg-tempban). The browser reconnects at
    once and the new connection is redirected to the CAPTCHA. New
    connections never reach these rules (their port is the CAPTCHA port
    after the redirect).
  - Test: `TestListedVisitorKeepAliveIsReset` (both kernels, a network
    namespace, `XG_DESTRUCTIVE_TESTS=1`): an open connection after the
    listing was "hung" before the fix, now reset within the second and
    the next connection gets the CAPTCHA; render checks in
    `TestCaptchaPassRendersIPDBOnly`.
  - The listing delay itself (WAF reports → portal sync → list push,
    up to ~10-15 minutes) stays: until then the address is not blocked
    (only the probed URL got 403).
  - **Rollback**: `backup-0.23.15`; agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.15: a solved CAPTCHA is no longer a whitelist**
  (2026-10-25). The owner asked whether one solved check gives an
  attacker on a shared server a free pass, and for how long. It did:
  - **Server**: `CaptchaSolved` stored a `tempallow` (default 12 h, up to
    7 days), which the kernel accepts first (`@tempallow accept`): every
    port open (port filter skipped), no DoS limit, and `AutoBan` skipped
    allowed addresses, so no new ban (brute force on SSH/mail/wp-login,
    WAF bans) and no IPDB report for that time.
  - **Portal**: `ipdb_cleared` kept a solved address off the fleet's IPDB
    for 30 days; for feed entries even when servers reported new attacks.
  - **Now**: a new kind `captchapass` (firewall.go `KindCaptchaPass`,
    kernel sets `cpass4/6`, ipset `xg_cpass4/6`). It only skips the IPDB
    drop (`ip saddr != @cpass4 ip saddr @ipdb4 ... drop_ipdb`) and the
    IPDB redirect (ban redirects come first); no accept. At most a day
    (`MaxCaptchaPass`; portal `MAX_PASS_MINUTES`, the 3 and 7 day choices
    are gone and longer saved values read as a day). `AutoBan` and the DoS
    ban sync end the pass (`endPass`) and mark the ban
    " (after a solved CAPTCHA)"; such a ban is not lifted by solving again
    (`PassRefused`: also in `captcha.pass` and `captcha.ticket`, so the
    portal records "server refused: … attacked after solving the
    CAPTCHA …"). The IPDB report of such a ban goes to the portal (passes
    are not in the report skip list). Passes still exempt the WAF's IPDB
    POST block and the login-page suspects list (rbl.go, central.go), so
    the person can post forms; other WAF rules apply. Old `tempallow`
    rows with comment "solved CAPTCHA" become passes of at most a day at
    start (`passesFromTempAllows`). Firewall » Temporary allow has "View
    CAPTCHA passes"; Check IP shows CAPTCHA-PASS.
  - Portal `CLEARED_DAYS` = 1, and a new report ends the clearing for
    every source (feeds too).
  - **ALTCHA tick from the logs**: 17 "box not ticked by a person" in 12 h,
    nearly all iCloud Private Relay visitors (87.81.x / 2606:54c1::,
    Safari) who passed on the second try 30-60 s later. Not reproduced
    (no WebKit in the container). The page now also counts presses
    (pointerdown/mousedown), touchend and a pointerup/touchend on the box
    as the tick, measures from the box appearing (at least 0.5 s, at most
    2 h), and the refusal reason carries the signals ("tick no after …
    ms, moves …, presses …, touch …, keys …"): read them in the reports
    if visitors still fail. Also fixed on the way: a function named
    `tick` clashed with the page's timer variable.
  - Tests: firewall `TestCaptchaPassRendersIPDBOnly` (nft and iptables
    rules), `TestCaptchaPassEndsOnNewBan` (both kernels),
    `TestOldCaptchaTempAllowsBecomePasses`; core
    `TestCentralCaptchaAgent` (refused pass); server ipdb-trust "clears a
    solved address for a day at most…", captcha "lets a solved check count
    for a day at most…", humanTick cases; browser "ALTCHA passes a single
    tap on a phone". `TestCaptchaSolvedWithoutRebuild` and
    `TestWhitelistReplacesTempAllow` now expect CAPTCHA-PASS.
  - **Rollback**: `backup-0.23.14`. Portal: the update command with
    `--branch backup-0.23.14`. Agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`
    (an older agent ignores `captchapass` rows; they expire within a day).

- **Release 0.23.14: the ALTCHA box glows until it is ticked**
  (2026-10-24). The owner asked for a soft shine so visitors see the box:
  a pulsing blue glow on its sides (`xglow`) and a light sweep across it
  (`xsheen`, an overlay with `pointer-events:none`, so clicks reach the
  box). Only while `data-state=unverified`; it stops once ticked. Reduced
  motion: a still glow. All three looks (classic, minimal, midnight). The
  real-browser test still passes (a real click ticks it). Rollback:
  `backup-0.23.13` (portal only; agents unchanged apart from the version).

- **Release 0.23.13: ALTCHA ticked by a person; IPDB CAPTCHA in the
  CAPTCHA page; agent updates and "80" checksums** (2026-10-24).
  - **ALTCHA no longer solves by itself**: the widget had `auto="onload"`,
    so the check passed within a second with nobody there. Now the visitor
    ticks the box; the page sends what the tick looked like (`hu`: a trusted
    click, time from page load, pointer moves, touch, keys) and the portal's
    `humanTick` refuses a check without a trusted click after at least
    0.7 s and a pointer move, a touch or a key (reason "box not ticked by a
    person"; the visitor sees "Please tick the box yourself" and Try again).
    A scripted browser can forge these signals: it only raises the bar; the
    proof of work, the hosting/other-address checks and the limits stay the
    real defence. Tests: `humanTick` cases in captcha.test.ts and
    `altcha-browser.test.ts` (real Chromium: no pass without a tick, a real
    click passes, a script `.click()` is refused; skipped without
    Playwright).
  - **IPDB / firewall CAPTCHA in the reports**: the agent marks visitors the
    firewall redirected (IPDB, bans) with `k=fw` (portal redirect and the
    site-mode frame; not the login gate). The portal records them as
    `captcha_events.source = 'firewall'` (migration 030; '' = login
    pages). CAPTCHA page » Recent checks has a "Sent by" filter (IPDB and
    firewall / Login pages) and a label under each website; the connector's
    `captcha_events` takes `source`. `k` is only a label: a visitor setting
    it changes no decision. Agents before 0.23.13 do not send it (their
    IPDB visitors show as login pages until they update).
  - **IPDB CAPTCHA for all servers**: CAPTCHA page » "IPDB and firewall
    visitors": each server's own setting (default, nothing pushed) / show
    the check on all servers / block only on all servers. Sent with
    `captcha.central` and `/api/agent/captcha/config` as `ipdb_captcha`;
    the agent then sets `ipdb.captcha` (central.go). With "all servers" a
    change of the per-server toggle (Firewall » CAPTCHA) is overwritten on
    the next CAPTCHA save.
  - **IPDB live list wording**: every row says BLOCKED; web connections
    redirected to the check also say "CAPTCHA offered". Those are visitors
    on ports 80/443; bots almost never load the page, so most never see a
    check. Mail, SSH and other ports are dropped.
  - **Agent update broken by a checksum starting "80"**: @fastify/compress
    takes a body whose first bytes look like zlib (e.g. "80", "XG", "H,")
    or gzip for already compressed, sends it as it is, yet labels it gzip.
    The streamed `.sha256` of a release starting "80" (1 in 256 releases)
    made every agent update fail ("gzip: invalid header"); this release's
    build hit it in `agent-update.test.ts`. Checksums are now sent whole
    (short, never compressed), and any string/Buffer answer starting like
    that is sent uncompressed (`looksCompressed`, app.ts onSend). Test:
    api.test.ts "sends checksums that start like zlib data readable".
  - Compared with cPGuard's IPDB article (information only, own code):
    fleet reports + AbuseIPDB + feeds, scored by reporters/reports and
    expiring (theirs: a cloud advisor every 2 h; ours rebuilt within
    minutes); trusted services and the fleet's own addresses never listed;
    ipset/nft drops; optional kernel log; Check IP (fw.check / IPDB page);
    an ignore list that survives reloads; IPDB CAPTCHA (theirs removes the
    address from the block; ours lets it in for the set time and keeps a
    solved address off the list for a while, `ipdb_cleared`: 30 days
    until 0.23.15, now a day at most, see 0.23.15).
  - **Rollback**: `backup-0.23.12`. Portal: the update command with
    `--branch backup-0.23.12` (the `source` column stays, unused). Agents:
    `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.12: CAPTCHA report review (24 h of 2026-10-24)**.
  `captcha_events`: 1,318 passed, 582 rejected, 75 failed.
  - **iCloud Private Relay visitors refused**: on 14 websites (schooltrack.pk,
    dubaiprofixer.com, mhsdigitals.com, primescopeusa.com, mus1i.com,
    cartogeek.com, …) the website saw 87.81.x or 104.29.x and the ALTCHA
    check was solved from Apple's 2606:54c1::/32; refused, then often
    passed with Turnstile from the person's own address. The ALTCHA
    fallback refused "hosting" addresses (AbuseIPDB calls the relays data
    centres). Privacy relays (`egressNetwork`) skip that check now, and
    87.81.0.0/16 joins the relay networks (portal `SHARED_EGRESS` and
    agent `waf.SharedEgressRanges`, which exempts them from IPDB POST
    blocks): an inference from this log (whois is not reachable from the
    container).
  - **CAPTCHA farm**: glasgowfitness.com's 23.82.99.148 (a proxy address)
    passed Turnstile every few minutes, solved from DigitalOcean and
    hosting addresses (134.199.132.123, 38.57.2.171, 23.80.89.36). A check
    solved from a hosting network for another address is refused now (both
    checks; relays excepted). (0.23.23: allowed again, for a 1-hour pass
    and 4 a day per address; the refusal shut out VPN visitors.)
  - **Why a check was refused**: new column `captcha_events.reason`
    (migration 029): strict setting, too many other addresses, ALTCHA daily
    limit / other network / hosting network, solved from a hosting network
    for another address, wrong answer, website server offline, and "server
    refused: <the agent's error>". Shown in Overview » CAPTCHA Page
    (Recent checks) and in the connector's `captcha_events` (`reasons`).
    algoking.pk (server1) refused 84.54.71.38's solved Turnstile check 16
    times in an hour: the agent's error was not visible before; read the
    reason after the update.
  - **Correct refusals seen**: AWS addresses (52.34.76.65, 54.70.53.60,
    54.71.187.124) on dozens of `030088xxx.xyz` sites; 198.23.158.93 and
    146.70.186.158 solved by their /24 neighbours (hosting).
  - Tests: server "lets privacy relays use ALTCHA, and refuses data
    centres solving for other addresses", the hosting test records its
    reason; agent `TestSharedEgressCoversRelays`.
  - **Rollback**: `backup-0.23.11`. Portal: the update command with
    `--branch backup-0.23.11` (the `reason` column stays, unused).
    Agents: `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.11: site-mode CAPTCHA out of reach; relay solvers**
  (2026-10-24). roxannebradley's owner (posts made by Meta's Muse agent)
  was blocked again: on roxannebradley.online the Muse browser was sent to
  `https://roxannebradley.online:7743/.xpguard/gate` and got "refused to
  connect"; on roxannebradley.org the ALTCHA check opened for 87.81.x was
  solved from 104.29.x (Cloudflare relay: iCloud Private Relay / WARP) and
  refused (2 on 10-24, 4 on 10-22).
  - **CAPTCHA port out of reach**: site mode sent suspects straight to
    the server's CAPTCHA port. A website behind Cloudflare (only 80/443
    and a few ports are proxied), agents' cloud browsers and office
    networks that only open 80 and 443 never reach it. The WAF now sends
    them to the portal's page with `g=<port>` (`rules.go`); the page
    (`probePage`) loads `https://<site>:<port>/.xpguard/ping.gif` (new on
    the agent's CAPTCHA server) and goes on to the gate there within 3
    seconds (pass cookie, no reload), or shows the check itself, which
    lets the address in through the pass list like portal mode (site-mode
    rules accept the pass list as well as the cookie). Only for a site the
    server confirmed (captcha.host); CSP `img-src` is that address only.
    Tests: `TestCentralSiteMode` (also on Apache: a pass-listed address
    gets in without a cookie), `TestSiteMode` (ping), server "goes to the
    CAPTCHA port only when the browser reaches it". Mixed versions: a new
    agent with an old portal shows the check on the portal (works); an old
    agent with a new portal is unchanged.
  - **Relay solvers**: the "solved for another address" allowance (3 an
    hour) was per solving address; on a shared relay address (104.28.0.0/15
    and the IPv6 relay ranges, Meta) strangers used it up. Solving from a
    shared egress network for an address outside it is now counted per
    website (`allowOtherAddress(…, host)`).
  - **Not verified from the container**: the owner of 87.81.0.0/16 (RIPE
    RDAP, ipinfo and Apple's Private Relay egress list are not reachable
    here). If the portal's CAPTCHA setting "strict" (`strict_ip`) is on, a
    same-family other address is still refused by design.
  - **Rollback**: `backup-0.23.10`. Portal: the update command with
    `--branch backup-0.23.10`. Agents:
    `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.10: files another product quarantined that we did not**
  (2026-10-24). The owner sent 51 files from a competitor's quarantine
  (kept in the session's scratchpad only, never committed). Each was
  compared with the official WordPress releases 6.0-7.1.3 (git mirror on
  GitHub; wordpress.org is not reachable from the container) and read:
  - **1 real malware, missed by our rules**: a hex-named file without an
    extension in `wp-content/uploads/`, starting with
    `<!-- https://t.me/… -->` then goto-flattened PHP with every string
    escaped and no eval: it fetches a WSO shell, an uploader, a mailer and
    a deface page from a web address into every site of the account and
    creates mail accounts for spam in every domain (writes
    `~/etc/<domain>/shadow` with `$6$` hashes and the dovecot mailbox
    folders). New behaviour rules on the source and its decoded literals
    (`kitBehaviour`, `escapedLiterals`): `PHP.Spam.MailAccountCreator`
    (writes a per-domain `etc/<domain>/shadow` next to mailbox folders)
    and `PHP.Dropper.RemoteSpreader` (escaped strings: a .txt/.php
    payload URL fetched and written into site folders it walks). A file
    without an extension is read as PHP when an HTML comment comes before
    `<?php` (`startsLikeScript`). Test `TestFleetMassMailKit` (inert
    fixtures, clean controls); 0 hits on WordPress 7.1.3, composer.phar
    and wp-cli.phar (about 7,000 files).
  - **31 corrupted WordPress core files** (`wp-includes/php-ai-client/…`,
    REST controllers, interactivity processor): no risky code; each is a
    block of another file's bytes or NUL bytes followed by the official
    file (several exactly twice the official size): a broken disk write
    or update. Not malware; WordPress's core check (CMS) and a core
    reinstall repair them; quarantining does not.
  - **13 translation files** (`classified-listing-*.l10n.php`): the PHP
    translation format of WordPress 6.5+ (NUL separates plural forms;
    "fsockopen" is a translated message): clean.
  - **wp-admin/moderation.php**: identical to WordPress's: clean.
  - **5 zip files of 79-115 bytes**: only the first bytes of an archive
    (`<hex>.zip` with `flat-publisher-vox/flat-publisher-vox.php`,
    `custom-headers-contact-lite.zip` holding `photo-video-editor.php`):
    the fake-plugin campaign's copies caught while being written. Nothing
    to run or judge; the complete copies are `Archive.*` detections.
  - **Testing note**: `xpguard-agent check` skips files owned by root (the
    system's); chown a sample folder to another user first.
  - **Rollback**: `backup-0.23.9`. Portal: the update command with
    `--branch backup-0.23.9`. Agents:
    `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.

- **Release 0.23.9: no offline AI model; fleet clean-up findings**
  (2026-10-24). The owner: "offline system khatm kro" (the AI is only a
  real AI, through the portal; the scanner's rules are what is trained),
  and permission for the clean-ups below.
  - **Offline model removed**: `agent/internal/ml` (the built-in logistic
    model and `model.bin`), the provider "Built-in AI model (free,
    offline)", the fallback to it while the portal AI is down (files now
    wait and are asked again), `ai-train` / `ai-score`, the fleet model
    (portal `train`, `/api/ai/train`, "Train fleet model now", the delta in
    `/api/agent/ai/sync`, now always null) and the features sent with each
    file. An old `provider: builtin` becomes `portal`. The signature
    engine (rules, families, hashes, YARA, WordPress/plugin checksums) is
    untouched: it never used the model. Tables `ai_samples` and
    `ai_models` stay (unused). Tests: `TestPortalOnly`,
    `TestPortalDownNoVerdict`, `TestFleetSyncLearnsHashes`, server
    "shares verdicts with every server, and no model update".
  - **WordPress cron jobs killed** (business500, server100: wslsecurity,
    kamaltubemills, hashi, techicon, diacompk …): cPanel runs
    `jailshell -c cd /home/u/public_html/wp; php -q wp-cron.php`; the
    process monitor read `/home/u/public_html/wp;` (with the `;`) as a
    deleted script and killed it. Shell words are trimmed of `;&|'"()<>`
    and the folder of a `cd` is no script (`TestAssessLevels`).
  - **~/.cache was never scanned**: malware run by cron from
    `~/.cache/.<40 hex>` (business500 baezonco, dndsnatu) was caught only
    by a learned hash. The files directly in `~/.cache` are scanned now;
    package caches below it stay skipped (`TestFleetHomeCacheLoader`).
    Real-time does not watch it (watch limit); the daily scan covers it.
  - **PHP archives judged by their members**: composer.phar (official
    2.8.12, sha256 f446ea71…, in aroojacademy's home) and wp-cli.phar were
    `PHP.Obfuscated.HaltCompilerPayload` (suspicious; with the AI only
    advising they would stay in quarantine). A well-formed phar is parsed
    (`scanner/phar.go`): its stub and every script are judged like zip
    members (`Archive.<signature>`); a file that does not parse is judged
    as before (`TestFleetPharByMembers`; checked locally on the real
    composer.phar and wp-cli.phar, not committed).
  - **A site's .htaccess written back by a kit** (business500 masfosur
    `public_html/.htaccess`, 784 returns) was removed on every return, so
    the site lost its permalinks; it is cleaned in place now
    (`removeReturned`, `TestFleetReturnedRootHtaccessCleaned`). New
    `finding.action` "clean_htaccess" (and in the connector) puts a
    quarantined site .htaccess back without the attack's blocks.
  - **Clean-up done through the connector (owner's permission)**:
    business500 masfosur 1,810 PHPLock .htaccess files quarantined (its
    lock allows `system_log.php`, `adminfuns.php`, `classsmtps.php`,
    `phpzipincs.php` …: the kit's shells; look for them in that account).
    websoul scans of alhafeezenterpri (6 campaign files quarantined: the
    variant `plugins/drift-optimizer-x/drift-optimizer-x.php.off`
    (`PHP.Obfuscated.FunctionTable`) and `<hex>.zip` copies; the AI called
    them clean at 95-100 %); webnsofts and npcihorg were queued behind it
    (scans 167, 168: read their findings next).
    server100 aroojacademy: nothing live besides composer.phar, which the
    scan quarantined and was restored at once (the phar fix above). Its
    reinfection source is not visible from the connector (no cron or
    process events, no database findings): check the account's WordPress
    admins and `wp_options` by hand.
  - **Seen, for the owner**: websoul royaldeseobysn
    `woocommerce-multi-currency.php` (a nulled plugin, "license/update
    bypass", `PHP.Suspicious.EncodedPayload`) was flagged and put back by
    the AI every 60 s, about 5,500 times until 10-23 (the portal sent the
    AI's own verdict back as "fleet", which did not clear it). 0.23.8 ends
    such loops (the AI does not restore). server100 aiwebtoo: a cron
    downloading `recon.py` into /tmp every minute was disabled (correct).
  - **Rollback**: `backup-0.23.8`. Portal: the update command with
    `--branch backup-0.23.8`. Agents:
    `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
    0.23.8 agents get no model update from a 0.23.9 portal (their offline
    model stays as shipped).

- **Release 0.23.8: the AI only advises; scanner review of the fleet**
  (2026-10-24). The owner asked for a review of the scanner on all
  servers and then: "AI auto restore khatm kr do", the AI scans and
  comments, the owner checks its comments against the files every night
  and the scanner is trained from that review.
  - **Why**: `ai_knowledge` (clean) held 146 recent verdicts, 118 of them
    `PHP.Obfuscated.SplitFunctionName`: the fake-plugin campaign
    (`mu-plugins/drift-optimizer.php`, `drift-runner-orb.php`, wp-content
    `db.php`, `object-cache.php`, `advanced-cache.php`, `.sc_<hex>/`
    folders, `<hex>.zip` copies; every copy a new hash, 12.5 KB, 21 KB,
    45 KB, 140 KB and 1.8-2.5 MB) called "Datum Backup Ultra", "SiteCare",
    "security plugin with obfuscation for anti-tamper" at 95-100 %, while
    the same model called other copies malicious at 100 %. The agent's
    untrusted list (0.22.x) kept those files from being restored, but every
    such verdict became a "clean" training label in `ai_samples` (the fleet
    model learned the campaign is clean), and AI restores of other
    signatures stayed automatic.
  - **Agent**: a clean AI verdict (this server's or the fleet's) never
    restores a file and never clears content (`ai.isClearedVerdict`: only
    an administrator, here or on the portal, clears; `clearFalsePositive`
    removed; `restore_clean` and `--restore-clean` have no effect). Files the
    AI put back before the update stay (status `ai_restored`, verdict
    marked `ai_kept` once on start), so running sites are not broken; an
    AI verdict never replaces an administrator's or a kept one (`ai.Save`).
    "Act on confident verdicts" still applies the virus action at >= 80 %
    malicious; "Only advise" turns that off too. Settings » AI text
    changed. Tests: `TestAICleanVerdictOnlyAdvises`,
    `TestAIRestoredBeforeStaysKept`, `TestFleetCleanDoesNotRestore`.
  - **Portal training**: the fleet update trains only on files an
    administrator reviewed (`ai_kb.overridden`, the label set by hand); the
    AI's verdicts stay with the samples as comments for the review
    (`gateway.train`; server test "shares verdicts and the trained model").
    The poisoned labels are left in the table and no longer used. Nightly
    review: the connector's `ai_knowledge` / `list_findings` show the AI's
    verdict and reason; set the true verdict in AI Scanner » Shared
    knowledge, then "Train fleet model now".
  - **Symlink false positives** (open findings on business500, next to
    its PHPLock files, business600 all 68, server1): root's links (cPanel
    `/home/user -> /home2/user` and back, CageFS skeleton
    `/var/cagefs/NN/user/home2/user`, `/opt/alt/redis/etc/*.conf`), links
    to a file of the link owner's own group they may read anyway (cPanel's
    `~/logs/<domain>.bkup -> /var/log/apache2/domlogs/...`, root:<account>
    0640) and links inside the owner's own home (npm `node_modules/.bin`)
    are no longer `Symlink.OtherAccount`; open findings of such links are
    closed when the agent starts (`CloseSafeLinks`, status cleared). Kit
    links to other accounts' wp-config.php stay flagged
    (`TestFleetSystemSymlinks`, `TestFleetSymlinkTheftKit`).
  - **Checked, no engine change**: the credential kits on business300
    (jpmilk `configWDP/`, 1,983 links) and server100 (ecommupscale
    `configEMQ/`, 1,627) were last scanned by 0.23.4 (21:08 on 10-23;
    0.23.5 came at 22:01): the next daily scan removes them. business500
    masfosur: 4,200+ PHPLock .htaccess files (the kit's
    `py|exe|php|…|suspected` lock) listed, not quarantined, because one
    account passed the spike limit (500 an hour) on its own; daily scans
    skip unchanged files, so they wait for the owner's bulk quarantine
    (open item 8). Reinfection: server100 aroojacademy
    (hamdeerpremiums.store) gets a new drift-optimizer.php every few minutes
    and websoul alhafeezenterpri / webnsofts / npcihorg have open findings
    of the campaign: the account needs cleaning (cron, database, admin
    users), not a rule.
  - **Rollback**: `backup-0.23.7`. Portal: the update command with
    `--branch backup-0.23.7`. Agents:
    `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
    The old agent treats `ai_kept` rows as not cleared (those files may be
    flagged again) and the symlink findings closed by 0.23.8 stay closed.

- **Release 0.23.7: web server memory (IPDB list copies)** (2026-10-23).
  The owner had another assistant look at the RAM on cloud2.xmarthost.com
  (a customer VPS, LiteSpeed). The "3.97 GB" in the report was 3.97 %;
  the real cost was the web server: every rule that reads a list file
  with `@ipMatchFromFile` keeps its own parsed copy of it in every web
  server process (measured on Apache: ~35 MB per 240,000-entry list).
  - **The IPDB list was loaded up to ~13 times per process.** The IPDB
    POST block read `ipdb-ips.txt` once per address source (3), and the
    CAPTCHA suspects file, which held the whole IPDB list plus the recent
    bans, was read by 6 gate/slot rules, and the soft-block strict list
    held it again. Measured: 460 MB per Apache worker before, 115 MB
    after (same lists). Now the IPDB list is read 3 times (the visitor's
    own address, behind Cloudflare, behind a local proxy) by mark rules
    right after the exemptions (`renderIPDBMarks`: `tx.xg_ipdb`,
    `tx.xg_ipdb_cf`, `tx.xg_ipdb_lp`, ids 7700060/7700061/7705061), and
    every other rule tests the marks:
    - IPDB POST block (same ids and messages as before): `TX:<mark> == 1`
      plus the `rbl-exempt` check.
    - CAPTCHA gate (`!ct.All`): one rule sets `tx.xg_suspect` for
      `TX:xg_ipdb == 1` unless the address is in
      `captcha-not-suspects.txt` (IPDB entries the agent left out of the
      suspects: solved, allowed, protected), one for
      `captcha-suspects.txt`, which now holds only the suspects that are
      not on the IPDB (`CentralFiles(c, ipdb)`: S \ I and I \ S, both
      small); gate and slot rules test `TX:xg_suspect`.
    - Soft block strict: the strict list without the IPDB
      (`strictList(true)`) plus rules on the marks (7700064-7700066).
    The marks are only used when the WAF is on, the IPDB list exists and
    IPDB POST or the central CAPTCHA is on (`Manager.ipdbMarks`);
    otherwise the rules are as before. Tests: `TestIPDBListReadOnce`
    (rendering), `TestIPDBMarksOnApache` (real Apache: IPDB suspect gets
    the CAPTCHA and 403 on POST, a left-out IPDB entry opens the page, a
    suspect off the IPDB still gets the CAPTCHA and may POST). LiteSpeed
    reads the same ModSecurity rules; check `ps -o rss -C litespeed` (or
    lsphp/httpd) on cloud2 before and after the update.
  - **SQLite**: the agent database runs WAL with `synchronous(NORMAL)`
    now (FULL waited for the disk on every WAF/connection log write);
    `TestDatabaseSynchronousNormal`.
  - **Report claims checked and not changed**: agent.log rotation (the
    agent rotates it at 50 MB itself), the ModSecurity audit log size
    (cPanel's SecAuditLog settings, not ours), 7700308 and 7701308 both
    present (the proxy variant, by design), port 7780 (both CAPTCHA ports
    bind in `sync()`), portal reconnects (45 s ping exists; needs the
    error text from agent.log to act on), conn_log size (capped at 7 days
    or 200,000 rows by design). Not done, possible later: `GOMEMLIMIT` for
    the agent; one IPDB read instead of 3 with a macro (LiteSpeed's macro
    support is unverified).
  - **Rollback**: `backup-0.23.6`. Portal: the update command with
    `--branch backup-0.23.6`. Agents: on each server
    `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`
    (the next WAF apply writes the old rules back). Nothing in the
    databases changed.

- **Release 0.23.6: CAPTCHA failures, Meta's Muse agent, AI agents**
  (2026-10-23). The owner switched the CAPTCHA to ALTCHA only, customers
  still failed it, and oxannebradley.org's owner (his WordPress posts are
  made by Meta's Muse agent, whose cloud browser logs in for him) was
  locked out; the owner had whitelisted 57.141.20.0/24 ("META") on every
  server. `captcha_events` (24 h): 2,846 ALTCHA rejected, 1,320 passed,
  360 failed. Findings and engine fixes:
  - **Meta's 57.141.0.0/16 was not trusted.** Meta (AS32934, RADb) is a
    trusted service, but since audit A4 F11 only RADb routes inside the
    service's known networks count, and 57.141.0.0/16 (meta-externalagent,
    Meta-ExternalFetcher, the Muse agent's cloud browser) was not one: the
    range ended up on the IPDB (fw.check: IPDB, not trusted), its visitors
    were sent to the CAPTCHA on login pages, and its IPv6 half
    (2a03:2880::/29) was trusted. Added to Meta's known networks; a cached
    built-in list is replaced by the release's (`TestMetaAgentNetworkTrusted`,
    `TestCachedBuiltinListUpdated`). Trusted = never banned or IPDB-blocked,
    no CAPTCHA, bot rules skipped; the CRS and the shop filter rules
    (7700510, same-origin marker) still apply: the same range scraped
    nextouch.pk's filters 53 times in 2 days and is still refused.
  - **The owner's whitelist of 57.141.20.0/24 should go** once 0.23.6 runs:
    a firewall whitelist turns the WAF off for the address
    (`ctl:ruleEngine=Off`, renderExempt), so every Meta crawler and every
    Muse user in the world reached the sites with no WAF at all. AI agent
    cloud browsers (Muse, ChatGPT agent, Gemini agent) are used by anyone,
    so they are never whitelisted; trusting them (above) is the safe level.
  - **Shared networks in the portal's ALTCHA checks** (`server/src/routes/captcha.ts`):
    one person's traffic on iCloud Private Relay / WARP (104.28.0.0/15,
    2606:54c1::/32, 2a09:bac0::/29) or Meta's cloud (57.141.0.0/16,
    2a03:2880::/29) moves between addresses and families: `sameNetwork`
    treats both families of one such network as the same network,
    `allowOtherAddress` does not count them (one Meta IPv6 address had
    solved for 16 Meta IPv4 addresses an hour and was refused), and the
    daily ALTCHA allowance there is per website (`altchaKeysFor`), so
    strangers on a shared relay address cannot use up a customer's.
    Tests in `server/test/captcha.test.ts`.
  - **Site mode: solved but never let in.** On the website's own address
    (central_mode "site") the page traded the portal's ticket with
    `fetch('/.xpguard/pass')`. A visitor the firewall redirects (banned,
    IPDB-listed) still holds the browser's earlier HTTP/2 connection to the
    website, while the agent closes its connections after every answer, so
    the pass went to the website, whose WAF refused it (7700711, IPDB POST):
    109.70.100.15 solved 5 times in a minute on roxannebradley.org, each
    followed by a 403 on `/.xpguard/pass`. The page now posts to the
    CAPTCHA port itself (`captcha.passURL`: https host:7743, or http
    host:7780 for an http page), with CORS for that website only
    (`allowSiteOrigin`); the cookie has no port, so the website gets it.
    The firewall accepts the CAPTCHA ports from everyone, not only
    redirected (DNAT) connections, so a banned visitor reaches them
    directly (`TestSitePassFromWebsitePort`, firewall tests).
  - **Shared egress for IPDB POST blocks**: `waf.SharedEgressRanges` now
    has all of the relays (104.28.0.0/15 and the IPv6 halves), as the
    portal (`TestSharedEgressCoversRelays`).
  - **AI agents in the trusted list**: Google user-triggered agents
    (Google-Agent, Gemini agent mode,
    developers.google.com/static/crawling/ipranges/user-triggered-agents.json)
    and MistralAI-User (mistral.ai/mistralai-user-ips.json), both read
    with the "scan" format. ChatGPT agent and ChatGPT-User already come
    from openai.com/chatgpt-user.json; Claude, Perplexity and Meta are
    there. Not added on purpose: agents without a published list (Manus,
    Genspark, cloud-browser services such as Browserbase or Cloudflare
    Browser Rendering): trusting them would trust a whole cloud that anyone
    rents. Browsers that run on the user's own computer (Perplexity
    Comet, ChatGPT Atlas, Claude in Chrome) come from the user's own
    connection and need nothing. The container used for 0.23.6 could not
    reach these URLs: check `trusted.status` on a server after the update
    (source "official", addresses > 0); an unreachable list shows
    "none" and changes nothing.
  - **Still to watch**: 23.82.99.148 (279 failed checks on
    glasgowfitness.com) and 43.172/43.173.x (Tencent cloud solving for its
    own neighbours) are bots; the failures are correct.
  - **Rollback**: `backup-0.23.5`. Portal: the update command with
    `--branch backup-0.23.5`. Agents: on each server
    `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`.
    Nothing in the databases changed.

- **Release 0.23.5: fixes from three server reports** (2026-10-23). The
  owner had another assistant inspect business200 (mypowerfulserver),
  business200 (websoulhostservers) and server1 (superfastcloudhosting)
  read-only; every claim was checked against the code and the live fleet
  (connector) first. Fixed in the engine, each with a regression test:
  - **Agent memory (3 GB)**: `agent.profile` on business200 and server1
    showed 3,065 MB in `IPTables.IPDBCounters`. The counter map's keys were
    substrings of the whole `ipset list` output, so every remembered entry
    kept one poll's output (~25 MB) alive. Keys are copies now and only the
    entries counted in the last reading are remembered
    (`TestIPSetCounterKeysAreCopies`, `TestIPDBHitsForgetsOldEntries`).
    The IPDB list minus protected addresses (250,000 entries compared with
    every protected address on each call, a fifth of a core) is built once
    per list version (`ipdbEntries`).
  - **AI restore loop**: a cached *fleet* "clean" verdict restored a
    quarantined file, but the scanner does not honour another server's AI
    (audit), so it flagged the file again a minute later: 1,445 rounds for
    aiomatic-automatic-ai-content-writer.php on business200. A finding whose
    content only the fleet found clean is now judged by this server's AI,
    and `clearFalsePositive` restores only on verdicts `ai.Clears` accepts
    (`TestFleetCleanFindingAskedHere`, `TestFleetCleanDoesNotRestore`).
  - **WAF settings rolled back on LiteSpeed**: on cPanel + LiteSpeed the
    test is `restartsrv_httpd --check`, which said "The httpd service is
    down" while LiteSpeed restarted (13 rollbacks a day on business200).
    That answer is asked again (3 x 10 s); if LiteSpeed is still down the
    rules (not yet loaded) are kept, LiteSpeed is restarted and checked
    again, and only a failure after that rolls back. A real refusal still
    rolls back at once (`TestLiteSpeedDownDuringRestartKeepsRules`,
    `TestLiteSpeedStillDownRestartsAndChecks`, `TestRefusedRulesStillRollBack`).
  - **"xpguard-waf.conf missing" (report K1)**: not a bypass. On cPanel,
    LiteSpeed loads the rules through modsec2.user.conf (the self test on
    business200 answered 403, CRS 4.30 active). The WebAdmin rule set
    "xPGuard" naming xpguard-waf.conf is a leftover of the stand-alone
    instructions and is switched off (`enableCensorship 0`). When such a
    rule set names a missing file, the agent now writes an empty
    commented file so LiteSpeed never fails if someone switches it on
    (`TestStaleLiteSpeedRuleSetGetsStub`).
  - **Credential theft kits (symlinks)**: folders of links such as
    `configTGQ/<account>-WordPress-public_html.txt` to every account's
    wp-config.php, .env and .accesshash (server1: 265,966 links, business300
    jpmilk 1,983, server100 ecommupscale 1,627) were only reported. A link
    to another account's files is now removed whenever the virus action is
    quarantine or disable (status "quarantined", qpath `link:<target>`;
    the target is never touched; Restore makes the link again with its
    owner; manual Quarantine of a link works too). Dangling links into
    another account's home that name a secret file (wp-config.php, .env,
    .accesshash, config.php, .my.cnf…, `scanner.SecretFileName`) count too:
    kits make one for every account and most targets do not exist yet
    (`TestFleetSymlinkTheftKit`).
  - **PHP upload through the WordPress uploaders (report bypass 1)**: a
    malicious plugin uploaded with a stolen admin session on business200
    passed because CRS 933110 scores 5 (threshold 10). New rule 7700315:
    a PHP file (php, phtml, phar, pht, phps) sent to update.php
    (upload-plugin/upload-theme), async-upload.php, media-new.php,
    upload.php, plugin-install.php or theme-install.php is refused: those
    only take zips and media. New rules watch until approved (open item 7);
    `TestWPPackagePHPOnApache` (real Apache + CRS; a control run with the
    rule off lets the PHP upload through).
  - **Padded web shells over the size limit**: PHP files (php, phtml,
    php3-8, pht, inc) over `max_file_size_mb` were never read. They are
    judged by their first and last 2 MB; official plugin files (whole-file
    checksum) stay trusted; other big scripts (JS bundles) stay unread
    (`TestFleetPaddedBigPHP`).
  - **CMS auto-update loop**: `wp plugin update` answers "already updated"
    when WordPress sees no newer release (premium or closed plugins), the
    version stayed and the update ran on every scan (business200: 774 times
    for template-kit-import, 1,962 failures). One try a week per site and
    installed version (KV `cms_update_try|…`), and only a real update is
    reported (`TestAutoUpdateNotRepeated`).
  - **Backup copies**: extracted cPanel backups in a home
    (`backup-M.D.YYYY_HH-MM-SS_user/`) and `softaculous_backups` are not
    watched in real time (`scanner.BackupFolder`; scheduled scans still
    check them) and not searched for CMS sites, whose old database logins
    gave hundreds of "Access denied" database checks a day
    (`TestDiscoverSkipsBackupCopies`).
  - **CAPTCHA port log spam**: scanners probing the public CAPTCHA HTTPS
    port wrote one "TLS handshake error" line each (235,000 in agent.log on
    business200); they are counted (`captcha.HandshakeErrors`), other server
    errors still logged (`TestHandshakeErrorsNotLogged`). The port stays
    public: site mode sends visitors to it.
  - **Audit false positives**: PHP 7.4-8.1 builds whose package changelog
    names CVE-2026-109618 (CloudLinux/cPanel backports) are no longer
    listed as open to PHP2Shell; a build from 2026-10-21 or later without
    the note is a "low" check item (`rpm -qf`; `TestPHPCVEsBackportedBuilds`).
    A private key header alone (README, JS bundles) is no longer a leaked
    key: the key body must follow (`TestLeakedKeyNeedsItsBody`).
  - **Checked and not changed** (claims that were wrong or are settings):
    the WooCommerce `LanguageFactory.php` "false positive" on server1 is a
    real dropper (writes a request-supplied XOR payload to a temp folder
    and includes it): it stays quarantined. IPv6 CAPTCHA redirect counters
    at 0 are expected (only addresses on the ban or IPDB lists are sent
    there, and the IPDB is mostly IPv4). agent.log is rotated by the agent
    at 50 MB. AI failures fall back to the built-in model and are asked
    again later. `block_php_upload`, the anomaly threshold, PK in ignored
    countries, quarantine retention and `max_file_size_mb` are per-server
    settings for the owner; cPanel's modsec_audit logrotate is not
    xPGuard's. Report items about account clean-up (business500
    masfosur PHPLock .htaccess files, the three symlink accounts, s5
    reinfection) are open item 8.
  - **Testing notes**: on a fresh Ubuntu container install `apache2
    libapache2-mod-security2 ipset yara iproute2`, then **remove the
    `modsecurity-crs` package** (Debian's CRS 3 loads next to ours and
    doubles the scores), clone CRS v4.18.0 (the suite's reference) for
    `XG_CRS_DIR`, and run each Apache test on its own with Apache stopped
    and `/etc/apache2/conf-*/xpguard-waf.conf` removed in between (the CRS
    tests leave the include). All 22 Apache tests pass on CRS 4.18; on CRS
    4.30 `TestExclusionsWithCRS`'s control check ("checkout passes even
    without the exclusion") fails, on 0.23.4 too: CRS 4.30 no longer flags
    that request.
  - **Rollback**: `backup-0.23.4` is the 0.23.4 code. Portal: the update
    command with `--branch backup-0.23.4`. Agents keep the previous binary
    after an update; on each server:
    `cp -a /opt/xpguard/bin/xpguard-agent.prev /opt/xpguard/bin/xpguard-agent && systemctl restart xpguard-agent`
    (or reinstall from the rolled-back portal's install command). A link
    quarantined by 0.23.5 cannot be restored by 0.23.4 (it has no
    `link:` support); nothing else in the database changed.

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
- **Full audit, first fix release** (0.23.0): ten module reviews
  (`docs/audit/A1..A10`, 156 findings) and fixes by area; status and what
  is still open in `docs/AUDIT.md` and GitHub issues #2-#11. Notable
  behaviour changes: the portal trusts proxy headers only from this host,
  private networks, Cloudflare and the master's own servers
  (`server/src/proxy.ts`, `TRUST_PROXY_IPS` for more); agents refuse
  downgrades and non-https updates (rollback to an older portal no longer
  downgrades agents) and fall back to `xpguard-agent.prev` after 3 failed
  starts; customers never read the master's IPDB, keys, knowledge base or
  WAF feed keys; file actions never follow an account's links; the WAF
  fixes of A3 were reverted (they weakened blocking in the Apache tests)
  and are still open.
- **Shop filter botnet** (0.23.4): business900 had 74 LiteSpeed
  restarts in a day: blacksoulltd.com got ~800 filter-URL requests a
  minute (`?filter_cat=…&filter_color=…&filter_size=…`) from ~28,000
  addresses with browser User-Agents, no cookies and a Referer; lsphp hit
  the account's LVE memory (OOM kills) and the 503 watchdog restarted
  LiteSpeed. Rule 7700510/7701510 let any Referer through. Now only a
  same-site browser signal exempts a cookie-less request: Sec-Fetch-Site
  same-origin with no Referer (+2000) or with this site's Referer (+5000).
  The rule still watches until it is approved in the portal (open item 1).
  Another assistant also added a .htaccess block and .user.ini limits to
  that account (backups next to the files).
- **PHP2Shell and agent memory** (0.23.3):
  - PHP2Shell (CVE-2026-109618, CVE-2026-109619, PHP releases of
    2026-10-21: unauthenticated RCE while PHP parses a request). WAF
    virtual patch 7701006 refuses form posts with a field name over 16 KB
    (the exploit needs megabytes). Audit check `php_cve` lists installed
    PHP interpreters older than 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, and
    7.4-8.1 (backports keep the version number: check the package date),
    with the interim mitigation (session.upload_progress.enabled = Off).
    xPGuard does not change php.ini itself.
  - Agents grew to ~5 GB on busy servers: the WordPress.org plugin
    checksums cache held up to 5000 versions as maps of maps (~1 MB each).
    Now sorted keyed 64-bit hashes (8 bytes a file), at most 4M (32 MB).
    `agent.profile` reports memory (RSS, heap, by area and function).
- **WHMCS admin saves on LiteSpeed** (0.23.2): my.galaxyhoster.com
  (cloud2, admin folder `/proka/`) could not save General Settings: CRS
  941100 scored 38. The WHMCS exclusion (7700027/28) raised the threshold
  in rules.conf, but the CRS setup loaded after it set it back (900110) and
  only the session threshold (30) applied; LiteSpeed ignores the ctl rule
  removal that let it pass on Apache. The exclusion now sets
  `tx.xg_app_save` and `appSaveSetup` (id 7700059, +1000 on a bad-reputation
  address) raises the threshold after the CRS setup, on every WAF level.
  Test `TestWHMCSAdminSaveWithoutCtlWithCRS` strips every ctl, as LiteSpeed
  runs the rules.
- **Audit fix release 2** (0.23.1): the A3 WAF fixes redone one by one
  with the Apache tests (forged WordPress cookies, Cloudflare and
  forwarded headers, API headers, PATH_INFO, settings values), plus the
  remaining scanner, firewall, CAPTCHA page and portal findings. Status
  per finding in `docs/AUDIT.md` ("Status after release 0.23.1"). Notable
  behaviour changes: a scanner whitelist entry without a folder no longer
  exempts PHP/JS/script files (use the full path); a forged
  X-Forwarded-For no longer skips the fake Googlebot/Bingbot rule; the
  0.5 AI endpoint is gone and each server may send 2000 files an hour to
  the portal AI; the agent websocket allows 3 unauthenticated sockets per
  server and 30 connections a minute per address.
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
  17.0.0.0/8, 104.28.0.0/15, 2606:54c1::/32 and 2a09:bac0::/29 since
  0.23.6) never get IPDB POST blocks: many real
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
7. **Approve 7700315** (PHP files sent to the WordPress uploaders, 0.23.5)
   after a few days of watch hits in Rule approvals.
8. **Accounts the 0.23.5 reports found taken over**: business500 masfosur
   (4,738 PHPLock .htaccess files still "detected": the signature had been
   paused, quarantine them after review); credential theft kits on server1
   minahsp1 (`plugins/dzrpqevxpk/configTGQ`, also its php.ini with
   disable_functions off), business300 jpmilk (`configWDP`) and server100
   ecommupscale (`configEMQ`): 0.23.5 removes the links at the next scan;
   clean the accounts, and since other accounts' wp-config.php and
   .accesshash could be read, change those database passwords and WHM API
   tokens. business200 (mypowerfulserver): a malicious plugin was uploaded
   on 2026-10-20 with a valid admin session (nsantosmaintenanceltd.co.uk):
   2FA and new admin passwords.
9. **Meta whitelist (0.23.6)**: done on 2026-10-23 on the 16 servers on
   0.23.6 (`trusted.refresh`: Meta 893 -> 923 addresses, the RADb routes
   of 57.141.x now count; google-agents 20 and mistral-user 4 from their
   official lists; `fw.check 57.141.20.4` TRUSTED-SERVICE; then `fw.remove`
   allow 57.141.20.0/24), and the same on business200.mypowerfulserver.com
   after its update: all 17 servers done.
10. **Not built yet**:
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
