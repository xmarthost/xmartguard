# xPGuard security plan (2026-10-30, from 0.23.42)

Sources: `reports/Shared hosting attack methods 2026.md` (items M1-M22,
I1-I16, written at 0.23.23) and the fleet incidents since: the ClickFix
kit, plugins uploaded with known passwords (server1 2026-10-28), the
11,966-admin farm (sawanysc), the symlink theft farm, fake plugins,
casino spam and phishing kits.

Work rule (owner): four parts, most important first. Each part is
finished, fully tested, released and installed on the fleet before the
next one starts. No WAF rule without watch mode first; no automatic
learning; every fix with a regression test.

## Coverage by category

✅ covered · ⚠️ partly · ❌ missing

| Category | What a host product must do | xPGuard now |
|---|---|---|
| Vulnerable plugins/themes | auto-update vulnerable versions; virtual patches within hours; catch what the exploit leaves (new admin, new plugin) | ⚠️ auto-update (0.23.26) and ~12 fixed virtual patches; no per-plugin patch feed (I2); no "anonymous request made an admin" rules (M7) |
| Stolen passwords / login | human check or stricter rules for logins from datacenter IPs; alert on admin login from a new place; count per username; 2FA option | ❌ brute force counts failed logins only; `login_gate` off; no login alerts (server1 2026-10-28) |
| Rogue admins, new plugins | read site DBs: new administrators, admin count jumps, hidden admins, plugins uploaded or activated | ❌ (M3); the CMS DB scan already connects to each site DB |
| Malware for visitors | ClickFix, skimmers, EtherHiding, redirects, SEO spam, phishing - in files and in the DB | ⚠️ files: ClickFix, phishing, casino, fake plugins (0.23.34-0.23.42); DB: injected scripts only; no skimmer families, no `widget_block` checks (M5, I4) |
| Persistence | mu-plugins, self-hiding plugins, .htaccess/.user.ini, hidden files, cron, SSH keys, user timers, immutable files | ⚠️ files and cron covered; no authorized_keys/systemd-user/at checks (M15), no chattr +i (M16), .htaccess cloaking partly (M6) |
| Webshells | uploaders, file managers, cookie-channel shells, PHP spawning shells | ⚠️ file rules (0.23.42); no process lineage (I3), no cookie-command rules (M21) |
| Supply chain | compare plugin files with the official release; flag nulled/trojanised packages | ⚠️ WordPress core checked; plugins not (M8) |
| Shared hosting cross-account | symlinks to other accounts, world-writable dirs, exposed secrets, kernel/isolation bugs | ⚠️ symlinks (full scan + realtime 0.23.42); no 0777 webroot audit, no kernel/sysctl audit (M4), secrets partly (I13) |
| Panel and server stack | cPanel/WHM, LiteSpeed, Exim, Roundcube, PHP versions and IoCs | ⚠️ PHP only (I1); no cPanel/LiteSpeed audit (M1) |
| Bots and floods | per-site budgets, under-attack mode, IP classes, cookie-bound passes, card testing | ⚠️ IPDB, CAPTCHA, DoS jail; M9, M10, M13, I6, I7, I9, I10 open |

## Part 1 - stop the attack chains seen on the fleet (P0)

1. **Admin watch** (M3): from the CMS DB scan, per site: new
   administrators since the last scan, admin count jump, admin names and
   e-mails of the farm patterns, admins hidden from the list. Alert in
   the portal and by mail; no automatic change (the owner decides).
2. **Plugin watch** (M3, I5): a plugin folder added or activated outside
   an update, a plugin missing from the list but active, `<name>_<epoch>`
   clones and empty marker folders. Alert, and the new folder gets a full
   scan at once.
3. **Login protection for stolen passwords**: a new option "login check
   for datacenter and foreign addresses": wp-login.php and xmlrpc.php
   logins from cloud/VPS ranges (and countries outside the server's own
   list) get the CAPTCHA first; the server's own country and residential
   users see nothing. Successful admin logins (302) are logged per site,
   with an alert for a new country or a datacenter address. Per-username
   failure counting (I8).
4. **Upload after login**: a WAF log line for `update.php?action=upload-
   plugin`, `theme-install`, `plugin-editor` saves, tied to the login
   address; alert when it follows a login from a new place.
5. **Panel and LiteSpeed audit** (M1): cPanel build, LiteSpeed plugin,
   LSWS, Exim, Roundcube versions against fixed versions; session-file
   and log IoCs. Read-only.

Release 0.24.0; tests; fleet update; check on server1 that the alerts
fire on the 2026-10-28 shapes and nowhere else.

## Part 2 - malware and persistence breadth (P1)

1. DB scanner breadth (I4): skimmers in `widget_block`, `wp_options`
   loaders, ClickFix and EtherHiding scripts stored in posts and options.
2. File skimmer families (M5): checkout-form scripts sending card fields
   to another host.
3. .htaccess conditional redirects and cloaking by user agent or referer
   (M6).
4. Non-cron persistence (M15): `authorized_keys` changes, systemd user
   timers, `at` jobs, shell profile loaders; immutable files in webroots
   (M16).
5. World-writable folders (0777) in webroots (`.tmb` farms) and exposed
   secrets on disk (I13).
6. Cookie-channel shell commands and POSTs to static files (M21, watch).

## Part 3 - answer new vulnerabilities in hours (P1)

1. Targeted virtual-patch feed for the plugins installed on each server
   (I2, watch first).
2. Generic "anonymous request creates privilege" rules (M7, watch).
3. Plugin integrity against the official release checksums (M8).
4. PHP worker starting a shell (process lineage, I3).
5. Kernel LPE and isolation sysctl audit (M4); PHP2Shell remainder (I1).
6. Application passwords and REST Basic-auth guessing (M18); phpMyAdmin,
   Roundcube and WebDisk login jails (M20).
7. Portal and update-chain hardening (M19).

## Part 4 - bots, floods and polish (P2)

1. IP classes and decay in IPDB; CAPTCHA passes bound to a cookie
   (I6, I7).
2. Per-site request budgets and automatic under-attack mode (M10).
3. WooCommerce Store API card-testing limits (M9).
4. Client fingerprint consistency (M13), HTTP/2 abuse readiness (M11),
   signed AI agents and Private Access Tokens (M12, M22), AI crawler
   budgets (I9).
5. Outbound egress monitor (M14), firewall DoS defaults (I10), PHP
   hardening audit (I12), realtime limits (I14), YARA (I15), probe
   learning as suggestions (I16).
6. Optional WordPress 2FA/passkeys (M17).

## Status

| Part | State |
|---|---|
| 1 | released in 0.24.0, on the fleet |
| 2 | in progress: locked (chattr +i) shells quarantined in 0.24.1 |
| 3 | waiting |
| 4 | waiting |
