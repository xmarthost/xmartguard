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
- Current release: **0.23.13** (see `VERSION`).

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
  `claude/keen-wozniak-eebt73`, 0.23.6 to 0.23.13 too), then push to `main`:
  ```
  git push -q -u origin <branch> && git fetch -q origin main && git merge-base --is-ancestor origin/main HEAD && git push -q origin HEAD:main
  ```
- **Releases**: bump `VERSION`, run the tests, commit as
  `Release x.y.z: …`, push. Then give the owner the update command:
  ```
  curl -fsSL https://raw.githubusercontent.com/xmarthost/xmartguard/main/deploy/setup-almalinux.sh -o /root/setup.sh && bash /root/setup.sh --domain app.xpguard.org --email support@xmarthost.com --billing-site https://xpguard.org
  ```
  Rollback is the same command with `--branch backup-<version>` (for
  0.23.13: `--branch backup-0.23.12`; see "Rollback" under 0.23.13 below);
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
    solved address off the list for 30 days, `ipdb_cleared`).
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
    checks; relays excepted).
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
