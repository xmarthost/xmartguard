# A3 - WAF audit (agent/internal/waf/)

## F1. "Logged-in user" / "admin save" relaxations are keyed on headers and cookies any attacker can send: the CRS can be switched off for any request
- Severity: CRITICAL
- Kind: security
- Confidence: HIGH
- Where: agent/internal/waf/level.go:88-139 (editorSetup, adminAreaSetup), level.go:216-226 (wpUserSetup), level.go:154-170 (sessionSetup); exclusions.go:222-266 (IDAdminPanel, IDWHMCSAdmin/Fetch, IDWPAdminExcl, IDWPAjaxExcl, IDWPCustomizer); rules.go:583-591, 633-636, 901-903, 928 (rules gated on `&TX:xg_wp_user "@eq 0"`); intel.go:280 (LoggedOut portal patches)
- Scenario:
  - `tx.xg_wp_editor=1` is set by any cookie *named* `wordpress_logged_in_<32 hex>` (the value is never checked, and the name is just md5 of the site URL, or any 32 hex chars). With WAF level normal (the default) or low, IDEditorCookie (7700040) then sets `tx.inbound_anomaly_score_threshold=100000` for every REQUEST_URI matching `(?:/wp-admin/|/wp-json/|[?&]rest_route=)`. So an unauthenticated attacker who sends `Cookie: wordpress_logged_in_00000000000000000000000000000000=x` and appends `&rest_route=` to **any** URL on **any** site, WordPress or not (e.g. `/shop.php?id=1' UNION SELECT ...&rest_route=`), is never blocked by the OWASP CRS. The same works on `/wp-admin/admin-ajax.php`, the endpoint behind most unauthenticated plugin vulnerabilities. The only exception is a source address already on the IPDB, Tor or ban lists (`xg_strict`).
  - IDEditorAuth (7700041) does the same for any `Authorization: Bearer xxxxxxxx` on /wp-json/ or `?rest_route=`.
  - IDEditorAdmin and IDWPUser+1000 trust `Sec-Fetch-Site: same-origin` and `Referer: https://<same host>/wp-admin/`. Attack tools set these headers freely; the claim "a page of another site cannot fake" holds against CSRF, not against a direct attacker.
  - adminAreaSetup (7700058) gives threshold 100000 to any request under an `/admin/`, `/administrator/` or `/backend/` segment that sends any cookie, `Sec-Fetch-Site: same-origin` and a same-host admin Referer.
  - IDWHMCSAdmin/IDWHMCSAdminFetch (7700027/28) apply `allow` plus `ctl:ruleEngine=Off` to any POST to `/<any folder>/(config*|clients*|orders|invoices|...).php` that carries a cookie named `whmcs` plus 6 or more letters and either a same-host Referer or `Sec-Fetch-Site: same-origin`. That covers `/anything/config.php` and `/x/configure.php` on every site, and it also turns off the xPGuard upload malware scan (7700101).
  - The injection-tag removals (IDWPAdminExcl, IDWPAjaxExcl with any Referer containing /wp-admin/, IDWPCustomizer, IDAdminPanel) apply on every level, strict included, to the same forged markers.
  - `xg_wp_user` (any cookie whose name starts with `wordpress_logged_in_`) also skips: the IPDB POST block and the Tor POST block (rules.go:928), user enumeration (7700303), the REST user list (7700304), the Gravity SMTP virtual patch (7701001: the hole is unauthenticated, so a fake cookie gets the data out) and every portal patch with `logged_out`.
- Fix: in the engine, treat these markers as hints, never as authentication:
  - Never lift the threshold above `sessionThreshold` on a client-supplied marker. Keep the RCE/LFI/RFI/PHP rules (930-934, 944) and the libinjection SQLi/XSS rules (942100, 941100) scoring for "editors"; relax only the HTML/JS-in-content families.
  - Match WordPress admin and REST paths on REQUEST_FILENAME (`^/+wp-admin/`, `^/+wp-json/`) or on the `rest_route` *argument* (ARGS_GET:rest_route), never on `[?&]rest_route=` anywhere in REQUEST_URI.
  - Replace the WHMCS `allow`/`ruleEngine=Off` with the threshold raise, and leave the upload scan in place.
  - Never gate IPDB/Tor POST blocks or virtual patches for unauthenticated vulnerabilities on `xg_wp_user`.
  - Regression test (Apache, like noctl_test): a request with a forged `wordpress_logged_in_<32hex>` cookie, Sec-Fetch-Site, Referer and `&rest_route=` carrying the crsProbeQuery payload must still get 403.

## F2. PHP-execution, web shell and virtual-patch block rules are bypassed with PATH_INFO, `//` or `/./` (the same class as the login-rule PATH_INFO fix)
- Severity: HIGH
- Kind: security
- Confidence: HIGH (PATH_INFO, `//` in fixed segments); MEDIUM (`/./`, which depends on ModSecurity phase-1 seeing the raw path)
- Where: rules.go:532 (IDSensitive `wp-config\.php$`), 535 (IDUploadsPHP), 536 (IDPHPInAssets), 542 (IDHiddenPHP), 597 (IDWPCoreDirect), 601 (IDWPAdminFake), 605 (IDWPLookalike), 612 (IDWPCachePHP), 620/624/626 (IDStaticPHP, IDRepeatDirPHP, IDHiddenDirPHP), 637 (IDVPFileManager `connector\.minimal\.php$`), 803 (IDWebshell), 817 (IDFleetNames), 822 (IDExploitProbe `eval-stdin\.php$`), 838 (IDRootProbe), 853 (IDNoUAPost)
- Scenario: PHP runs `/wp-content/uploads/2024/x.php` for `/wp-content/uploads/2024/x.php/a`. central_test.go:263 already records this for the login rules. Every pattern above ends in `\.(?:php…)$`, so the request with `/a` appended is not blocked. I checked this with the rules' own regexes: IDUploadsPHP matches `/wp-content/uploads/2024/x.php` but not `.../x.php/a`. `/wp-content//uploads/x.php` and `/wp-content/./uploads/x.php` also miss IDUploadsPHP: it has no `/+` there, and no rule uses `t:normalizePath`. Result: an uploaded web shell, the WP File Manager CVE-2020-25213 connector, PHPUnit eval-stdin and every name on the fleet-learned shell list are all reachable.
- Fix: end every "PHP file" pattern with `\.(?:php[0-9]?|phtml|phar|pht)(?:/|$)`, as the login fix did. Add `t:normalizePath` (or `/+` and `(?:\./)*` in the fixed segments) to the REQUEST_FILENAME transformations. Add one table test that renders all rules and checks each blocking PHP rule against `x.php`, `x.php/a`, `//dir//x.php` and `/./dir/x.php`.

## F3. Forwarded-address checks trust X-Forwarded-For / X-Real-IP from any client behind Cloudflare: IPDB/Tor/blocked-IP blocks can be bypassed and bad-reputation marking cleared
- Severity: HIGH
- Kind: security
- Confidence: MEDIUM (the exact effect relies on ModSecurity v2 setting TX:1 from the last matching target of a multi-target rule)
- Where: rules.go:941-944 (rblRule id+1000), rules.go:968-970 (IDProxyBlocked), softblock.go:73-78 (byAddr, used by IDSoftVerified, IDSoftStrict and IDSoftCountry)
- Scenario: when REMOTE_ADDR is a Cloudflare range, the chain captures `^\s*(ip)` from `CF-Connecting-IP|X-Forwarded-For|X-Real-IP` and tests TX:1. Cloudflare passes `X-Real-IP` through unchanged and appends to a client-sent `X-Forwarded-For`, so the client controls those values. TX:1 ends up holding the last target that matched (X-Real-IP).
  - An IPDB-listed or Tor visitor behind Cloudflare who sends `X-Real-IP: 17.0.0.1` makes the chain test 17.0.0.1. That address is not listed and is even rbl-exempt, so POST, Tor and proxy-blocklist blocking is skipped.
  - In soft blocking, the same header carrying an address from a whitelisted country runs IDSoftCountry+1, which does `setvar:!tx.xg_strict` and sets the relaxed threshold. That clears the bad-reputation flag of a listed visitor and re-enables the F1 relaxations for them.
- Fix: render separate rules per proxy type. For Cloudflare ranges read only `CF-Connecting-IP` (as IDTrustedCF already does). For local proxies (127.0.0.1/::1) read the header that proxy sets, taking the last X-Forwarded-For hop. Never let rules that relax or clear a flag (verified, country) read X-Forwarded-For/X-Real-IP. Test: a Cloudflare-sourced request with CF-Connecting-IP on the IPDB and a forged X-Real-IP must still be refused POST.

## F4. Fake-Googlebot/Bingbot rule is skipped by adding any X-Forwarded-For header; a fake crawler then also passes the shop scrape/facet rules
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: rules.go:909-916 (IDFakeSearchBot), rules.go:871, 876-888 (search-engine exemption by User-Agent)
- Scenario: `User-Agent: Googlebot` plus `X-Forwarded-For: 1.1.1.1` sent directly (not through a proxy) fails the chain link `&REQUEST_HEADERS:X-Forwarded-For "@eq 0"`, so the request is not blocked. IDCrawlerFacets and IDShopScrape exempt anything whose UA says googlebot/bingbot, so such a scraper walks every uncached shop filter.
- Fix: skip the fake-bot test only when REMOTE_ADDR is in proxy-ranges.txt. For Cloudflare, test CF-Connecting-IP against trusted-ips.txt instead of skipping. Test: direct request with a Googlebot UA and a forged XFF gets 403.

## F5. IPDB POST block is switched off by any request carrying an "API" header name
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: rules.go:950-953 (IDIPDBPostAPI), rules.go:1089 (reAPIHeader)
- Scenario: a listed address posting to wp-login.php or a contact form with `Authorization: x` (or `X-Foo-Token`, or any header name containing "signature") sets `tx.xg_api=1`, and the IPDB POST rule and its +1000 variant are skipped. Bots can add this header at no cost.
- Fix: grant the exemption only when the header is present and the request looks like an API call: no Cookie, not a browser Accept, and a path matching the API/webhook pattern already used by IDNoUAPost. Or exempt only trusted-service addresses. Test: a POST to /wp-login.php from an IPDB address with `Authorization: x` stays blocked.

## F6. WAF settings strings go into ModSecurity config unvalidated: one typo freezes the WAF, and a quote can add actions
- Severity: MEDIUM
- Kind: security / failure-mode
- Confidence: HIGH
- Where: rules.go:471-485 (WhitelistIPs into `@ipMatch` without validAddr; WhitelistDomains via QuoteMeta), rules.go:677-684, 689-691, 715-718 (LoginURLs via QuoteMeta); settings.go:671, 699-700 only trim and dedupe
- Scenario:
  - A whitelist entry such as `example.com` or `1.2.3.4/33` gives an invalid `@ipMatch`, so the config test fails and the install rolls back. Every later apply fails the same way, so the WAF is frozen: new CAPTCHA passes, IPDB/Tor lists and settings are never applied, and visitors who solve the CAPTCHA are sent back to it.
  - `regexp.QuoteMeta` does not escape `"`. A login URL or whitelist domain containing `" "id:…,exec:/path` closes the operator and adds actions such as exec (run as the web server user) or ctl:ruleEngine=Off. These values come from portal settings, so a portal account that can edit WAF settings, or a compromised portal, can run commands on servers.
- Fix: validate in settings.normalize: WhitelistIPs with validAddr, WhitelistDomains with ValidDomain (allowing `*.`), LoginURLs against `^/[A-Za-z0-9._~%/-]{1,200}$`. Also filter again in Render so a bad value is dropped instead of breaking the file. Test with inert values containing `"`, spaces and invalid IPs: the rendered file must not contain them and must pass `httpd -t`.

## F7. Features that rely only on ctl:ruleRemoveById do nothing on LiteSpeed (portal and learned exclusions, domain whitelist, disabled rules)
- Severity: MEDIUM
- Kind: bug
- Confidence: HIGH (the handoff documents that LiteSpeed ignores rule removal; these paths have no tx-marker or config-time fallback)
- Where: exclusions.go:274-309 (writeExcl: every portal rule exclusion and learned exclusion), rules.go:479-485 (IDWhiteDomains), rules.go:514-527 (IDDisable; IDUploadMalware is rendered even when disabled), exclusions.go:183, 189-198, 214-220 (IDHostingBase, IDCPanelMailCfg, IDDeviceIclock, IDCPanelPaths, IDThemeColorCSS, IDSiteBeacons)
- Scenario: on a LiteSpeed server an admin accepts a learned false positive or adds an exclusion in the portal, and the 403s continue. A whitelisted domain is still inspected. Switching off 7700101 still scans uploads. `css/color.php?primary_color=F7931A` is still blocked by IDStaticPHP (7700321), and the hosting-default CRS removals (941310 Urdu/emoji, 942550) do not apply.
- Fix: for xPGuard's own rules, never render a disabled rule (use rule() for 7700101) and gate rules with a tx marker instead of ctl. For exclusions with no domain or path, emit config-time `SecRuleRemoveById` after the CRS include, which every engine applies. For scoped ones, use the threshold-raise mechanism (proven on LiteSpeed), or `SecRuleUpdateTargetById` where the target is known. Extend noctl_test to strip every ctl and check that exclusions, the domain whitelist and the colour-CSS exception still work.

## F8. The WAF auto-ban can ban a Cloudflare edge address
- Severity: MEDIUM
- Kind: bug
- Confidence: HIGH
- Where: waf.go:1033-1036, 1091-1098, 1126-1136 (maybeBanBlocked); rules.go:941-948, 968 (rules whose matched REMOTE_ADDR is always the proxy)
- Scenario: IDProxyBlocked (7700701), Tor +1000/+2000 (7701712/7702712/7701713/7702713) and the IPDB +1000 rule only match when REMOTE_ADDR is a proxy, so the event IP is a Cloudflare edge. Only the IPDB variants are in noBanRules. After WAFBanThreshold (15) such blocks in the window, `Firewall.AutoBan(<Cloudflare IP>)` runs. The same happens for every rule on a server without mod_remoteip or LiteSpeed's client-IP setting. The firewall spares it only when trusted services are on, Cloudflare is not disabled and its list has already been downloaded (first boot, a failed fetch or `TrustedDisabled: cloudflare` all ban it). The result is that every proxied site on that edge is cut off for the ban time.
- Fix: in the WAF ban path, never count or ban an address inside ProxyRanges, and add IDProxyBlocked and the Tor +1000/+2000 ids to noBanRules. Unit test: an event from 104.16.0.1 never reaches AutoBan.

## F9. "Login attempt" rules count every POST, not failed logins, and real users get banned
- Severity: MEDIUM
- Kind: bug
- Confidence: HIGH
- Where: rules.go:662-685 (IDLoginXMLRPC, IDLoginJoomla, IDLoginOpenCart, IDLoginCustom); waf.go:1078-1089 (maybeBan)
- Scenario: each POST to xmlrpc.php counts. That includes pingbacks, Jetpack and mobile-app sync, and any app calling system.listMethods. Successful Joomla/OpenCart logins and every POST to a custom protected URL count too. With the defaults (BFThreshold 10, window 10 min), a site owner using a desktop or mobile XML-RPC client, or a busy custom form URL, is banned with the reason "WAF: 10 failed … logins".
- Fix: count failures only, as the WordPress rule does (phase 3, `RESPONSE_STATUS @streq 200`). For Joomla and OpenCart a successful login redirects (303/302), so count the 200 response. For XML-RPC count only authenticated methods (wp.getUsersBlogs and similar, or `system.multicall`) and, where the response body is available, faults. Test: a successful login POST (302) and a pingback POST do not count.

## F10. A failed reload leaves new rules on disk, is never retried, and the error disappears on the next apply; cPanel's "config test" may not test the config
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: HIGH for the no-retry path; MEDIUM that `restartsrv_httpd --check` checks service status, not syntax
- Where: install.go:403-405 (`!changed` returns nil), install.go:469-485 (no rollback after a reload failure), install.go:194 (configTest `restartsrv_httpd --check`), waf.go:551-559 (m.err cleared)
- Scenario: the reload fails (timeout, LiteSpeed busy, restartsrv's own syntax check refuses). The rule files stay written and the error is shown once. On the next Apply nothing has changed, so installMode returns nil, m.err is cleared, and the self-test passes on the old running rules, which also contain the self-test rule. The server keeps running stale rules with no warning. If the cPanel "--check" step does not validate syntax, an invalid file is also left on disk and Apache fails to start on the next unrelated restart (EasyApache, cPanel update, reboot).
- Fix: use `httpd -t` / `apachectl -t` as the config test on cPanel too. On a reload failure either roll back the files or keep a `reloadPending` flag that makes the next apply reload even when nothing changed, and keep m.err until a reload succeeds. Test with a fake reload command that fails once.

## F11. waf_events cleanup runs a DELETE on every recorded event
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: waf.go:1069-1076
- Scenario: `e.ID` is always 0 for a parsed event, because it is never set before the insert, so `e.ID%512 == 0` is always true. Every WAF hit costs an extra `DELETE … WHERE at < ?`, which doubles write load during floods.
- Fix: use the insert's LastInsertId, or a package counter, for the every-512 check.

## F12. cPanel user panel "WAF events" is always empty
- Severity: LOW
- Kind: contract
- Confidence: HIGH
- Where: waf.go:1069-1071 (record writes e.User, which nothing sets), waf.go:1162-1163; core/panel.go:122-129 (filter `user = <account>`)
- Scenario: account owners never see their sites' WAF hits, because every row has `user = ''`.
- Fix: in record, set e.User from the host using the domain-to-owner map (/etc/userdomains) that the panel code already uses elsewhere. Test: an event for a user's domain is listed for that user only.

## F13. Concurrent audit log: one goroutine per index line, unbounded
- Severity: LOW
- Kind: leak
- Confidence: HIGH
- Where: auditlog.go:423-428
- Scenario: under a flood, each index line starts a goroutine that sleeps 1 s, reads a file and blocks sending on a 256-slot channel. Meanwhile tailLogs does two DB writes per event. Goroutines and open entry files pile up without limit.
- Fix: one worker with a bounded queue of pending entry paths; drop entries (and count the drops) when the queue is full.

## F14. CAPTCHA redirects build the target from the raw Host header (port included)
- Severity: LOW
- Kind: bug
- Confidence: MEDIUM
- Where: rules.go:706, 775 (`https://%{REQUEST_HEADERS.Host}:%d/...`)
- Scenario: a site reached on a non-default port (Host `example.com:8080`) or by an IPv6 literal is redirected to `https://example.com:8080:<port>/.xpguard/gate`, which is an invalid URL, and the visitor cannot pass the login gate.
- Fix: capture the host without its port into a tx variable (as IDSessionHost does, `^([^:]+)`, with bracket handling for IPv6) and use `%{tx.xg_host}`.

## F15. Custom-rule validator misses operator aliases and the proxy action
- Severity: LOW
- Kind: security
- Confidence: MEDIUM
- Where: rulesets.go:376 (reForbiddenAction)
- Scenario: `@pmf` and `@ipMatchF` (the short forms of `@pmFromFile` and `@ipMatchFromFile`) pass the `@\w+fromfile` check, so config-time file reads as root are possible. The `proxy:` action, which needs mod_proxy, is not refused, so portal custom rules could make every server proxy requests to any URL (SSRF). This only matters if the portal is compromised, since only the portal sets custom rules.
- Fix: refuse `@pmf\b`, `@ipmatchf\b` and `\bproxy\s*:` as well; add these to the validator test table.

## F16. The Bad Bot blocker list accepts very short entries, so one typo blocks every visitor
- Severity: LOW
- Kind: failure-mode
- Confidence: HIGH
- Where: rules.go:1013-1020 (BotFiles), settings.go:702-710
- Scenario: `@pmFromFile` matches substrings without regard to case. An entry such as `a`, `Mozilla` or `Chrome` returns 403 to every browser (except on /robots.txt). Only `xx` and `user-agent` are retired.
- Fix: in normalize, drop entries shorter than 4 characters and entries that occur in common browser User-Agents (`mozilla`, `chrome`, `safari`, `applewebkit`, `gecko`, `windows`, `android`, `iphone`). Test with these inert strings.

## Area summary

I read every non-test file in agent/internal/waf/ in full (waf.go, rules.go, install.go, level.go, rulesets.go, exclusions.go, intel.go, learn.go, monitor.go, softblock.go, auditlog.go, remotecheck.go, selftest.go, captchasent.go). I also read the settings sanitizers they rely on (settings.normalize, CleanExclusions), firewall.AutoBan, trusted.WAFCIDRs and the core feeds of the WAF lists. `go vet` is clean and `go test ./internal/waf/` passes.

Overall health:
- The rule generator is careful about chain/ctl placement, LiteSpeed's missing ctl support for the bot and IPDB rules, list-file hygiene (placeholder IPs, /32 masks), portal patch validation (intel.go is solid: quoting is safe, ids are confined) and reload throttling.
- The weak spot is trust in client-supplied signals. "Logged-in WordPress user", "admin save", "API call", "same-origin" and forwarded addresses are all read from headers and cookies the attacker controls. The relaxations they unlock are very large: the CRS threshold goes to 100000, WHMCS gets `allow` plus engine off, and IPDB/Tor checks are skipped (F1, F3, F4, F5).
- The second weak spot is the `\.php$` anchoring across the PHP-execution rules (F2). It is the same mistake fixed for the login rules in 0.22.26.

Riskiest spots: level.go editorSetup/adminAreaSetup, exclusions.go WHMCS/admin-panel rules, the rblRule/softBlock header capture, and the end-anchored PHP patterns in rules.go. On the operations side: settings strings rendered without validation (F6), exclusions that do nothing on LiteSpeed (F7), and the reload-failure path (F10).
