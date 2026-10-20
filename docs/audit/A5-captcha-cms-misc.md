# A5 audit: captcha, cms, mail, notify, audit, monitor, panel, sysinfo, layout, settings

## F1. Banned visitors bypass the firewall ban for any GET URL through the "machine file" proxy (`/.well-known/../`)
- Severity: HIGH
- Kind: security
- Confidence: HIGH (bypass of the ban); MEDIUM (WAF also sees the server's own address)
- Where: agent/internal/captcha/passthrough.go:32-37 (machinePath), :105-137 (serveFromSite); captcha.go:211-216
- Scenario: A banned or IPDB-listed address is NAT-redirected to the CAPTCHA server. The server checks `machinePath` against the decoded, uncleaned `r.URL.Path`, so `\.well-known/.*` matches `GET /.well-known/../wp-login.php?x=...` or `/.well-known/%2e%2e/<any page>`. Go's server does not clean paths for a plain Handler, and `httputil.ReverseProxy` forwards the request-URI unchanged (checked with a scratch program: the backend got `RequestURI=/.well-known/../wp-login.php?x=1` and `/.well-known/%2e%2e/wp-login.php`). The proxy sends it to the original destination (the site, port 80/443) with any `Host` the client chooses. Apache and LiteSpeed normalise `..`, so the banned address gets full GET/HEAD access to every vhost: scraping, GET-based scanning and exploitation, xmlrpc/REST reads. The request also reaches the web server from the server's own address (XFF is only appended), so IP-based WAF and IPDB rules that test REMOTE_ADDR may not apply to it.
- Fix: in `MachinePath`, reject a path that is not canonical: `path.Clean(p) != p`, or a raw path (`r.URL.RawPath` / `EscapedPath()`) that contains `%2e`, `%2f`, `%5c`, `..` or `//`. Then rebuild the outgoing URL from the cleaned path. Limit `.well-known/` to `acme-challenge/`, `pki-validation/` and `security.txt`, and do not forward the query string. Regression test: `/.well-known/../x`, `/.well-known/%2e%2e/x` and `/.well-known/./../x` get the CAPTCHA or a 403, never the proxy.

## F2. A cPanel user can crash the root agent with a huge sparse wp-config.php
- Severity: HIGH
- Kind: security / failure-mode
- Confidence: HIGH
- Where: agent/internal/cms/dbscan.go:30 (ReadWPConfig, called from cms.go:275, dbclean.go:105/188); cms/vulns.go:200,350 (EnsureRealCron/RemoveRealCron); audit/audit.go:453 (wordpressChecks)
- Scenario: The account runs `truncate -s 1T public_html/wp-config.php`. A sparse file uses no quota, `detect` sees a regular file, and the file sits next to a real `wp-includes/version.php`. The nightly CMS scan (DB scan is on by default) calls `os.ReadFile`, which allocates the file's full size up front. Go aborts with `fatal error: out of memory`, which cannot be recovered (reproduced in a scratch program: "cannot allocate 1099515822080-byte block"). The whole agent dies: WAF sync, the firewall manager and the CAPTCHA all stop with it. After a restart the scan is due again and crashes again the next night. The audit's `wordpressChecks` crashes the same way. A compromised site can use this to switch xPGuard off on that server.
- Fix: add one helper, `readSmall(path, max)`: open with `O_NOFOLLOW|O_NONBLOCK`, `Fstat` it, require a regular file with size <= 1 MB, then `io.ReadAll(io.LimitReader(f, max))`. Use it for every user-controlled file the agent reads as root in cms/ and audit/. Regression test: a sparse 10 GB wp-config.php fixture returns an error without allocating.

## F3. Settings Patch merges array elements into the old ones: removing a WAF rule exclusion can narrow the remaining ones
- Severity: MEDIUM
- Kind: bug / contract
- Confidence: HIGH
- Where: agent/internal/settings/settings.go:592-608 (Patch: `next := st.cur; json.Unmarshal(patch, &next)`); web/src/pages/AllowList.tsx:69,109
- Scenario: `encoding/json` decodes an array into the existing slice element by element and leaves fields the JSON omits as they were (verified: old `[{rule:1,domain:"a.com"}]` patched with `[{"rule":5}]` gives `{5 a.com}`). The portal omits empty `domain`/`path` (`undefined`). Start from `[{rule:1, domain:a.com, path:/x}, {rule:942100}]` and remove the first entry. The patch is `[{"rule":942100,"note":..}]` and becomes `{942100, a.com, /x}`, so an exclusion meant for every site now covers only one site and path. False positives come back with no visible cause. `Scanner.DBWhitelist` and any future `[]struct` field have the same problem.
- Fix: in `Patch`, decode the patch into a `map[string]json.RawMessage` tree, or zero every slice field that the patch names before calling `Unmarshal`. A simpler fix is to deep-copy `st.cur` with Marshal/Unmarshal and then set to nil each slice the patch contains. Test: removing the first of two exclusions keeps the second one's empty domain and path.

## F4. A failed settings Patch still changes the live settings in memory (slices share their backing array) and races with readers
- Severity: MEDIUM
- Kind: bug / security
- Confidence: HIGH
- Where: agent/internal/settings/settings.go:592-607; core/core.go:767 (`append(cur, path)` on a slice from `Get()`)
- Scenario: `next := st.cur` copies only the slice headers. Unmarshal writes array elements in place into the shared backing array when its capacity allows (verified: `cur.L` became `["bad\"x", ...]` after decoding into `next`). A patch such as `{"waf":{"bot_list":["x\"y"]}}` fails `validate` and returns an error, yet `st.cur.WAF.BotList[0]` now holds the rejected value. The next `WAF.Apply` renders it into the ModSecurity configuration, so validation can be bypassed for strings that go into rule files. It is also a data race: `Get()` callers iterate the same arrays while Patch writes them. `core.go:767` appends to a slice it got from `Get()` and writes past its length into the shared array.
- Fix: deep-copy before decoding (`b, _ := json.Marshal(st.cur); var next Settings; json.Unmarshal(b, &next); json.Unmarshal(patch, &next)`), and have `Get()` return copies of the slices (or document them as read-only and use `slices.Clone` at line 767). Test: a rejected patch leaves `Get()` byte-for-byte unchanged.

## F5. The Outgoing Spam Monitor holds or suspends the wrong cPanel account (owner taken from the spoofable envelope sender)
- Severity: MEDIUM
- Kind: security / bug
- Confidence: MEDIUM (depends on cPanel letting local users set `-f`, which is its default)
- Where: agent/internal/mail/osm.go:341-346; core/extras.go:32-38 (mailOwner)
- Scenario: For a local submission, Exim's `U=` is the real Unix account. `raise` still sets `e.User = Owner(m.Sender)`, the account that owns the envelope sender's domain, and uses `LocalU` only when no owner is found. A script in account A that sends 50 messages a minute with `-f x@b-domain.com` makes xPGuard run `hold_outgoing_email` / `suspend_outgoing_email user=B`. The innocent account B loses its mail and the spammer A keeps sending. Any account can also do this on purpose.
- Fix: for local submissions (`m.Auth == ""`), the account is `m.LocalU` (mapped through the cPanel user list). Use `Owner(sender)` only for authenticated logins (`m.Auth`, whose domain is authoritative). Test: a `U=userA` line with sender `@b.com` puts the event on userA.

## F6. Outgoing spam limits are evaded by rotating the envelope sender
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: agent/internal/mail/osm.go:92-97 (key), :262-297
- Scenario: Local submissions are counted per `LocalU + " (" + Sender + ")"`. A PHP mailer that passes a random `-f` for each message (common in spam kits) creates a new counter every time and never reaches 50/min or 300/h. The account can send unlimited spam with no event, hold or suspension.
- Fix: count local submissions per `LocalU` (the account) and keep the sender only as detail. Optionally keep a second limit per sender. Test: 60 messages from one `U=` with 60 different senders trigger the per-minute event.

## F7. CMS and audit follow symlinks as root: cross-account DB scan/clean and writes into another account's wp-config.php
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: agent/internal/cms/discover.go:72-87 (isFile uses Stat); dbscan.go:30; dbclean.go:105-160, 181-211; vulns.go:195-215, 340-366 (os.WriteFile on wp-config.php as root); audit/audit.go:416-453
- Scenario: Account A makes `~/public_html/wp-config.php` a symlink to `/home/B/public_html/wp-config.php` (any user can create such a link). `detect` follows it and sees a regular file. The DB scan connects with B's credentials and stores B's injected rows as findings of A's site. "Clean selected" or "Restore" then changes B's database. With WP-Cron override on, `EnsureRealCron` reads and rewrites B's file as root (adds DISABLE_WP_CRON), and `RemoveRealCron` rewrites it too. A link to any root-readable file that contains `<?php` gets the same root write.
- Fix: open wp-config.php (and the other files these packages read or write) with `O_NOFOLLOW` and check with `Fstat` that the owner uid is the account's uid. Write in place through the same descriptor (or as the owner with `runuser`). Skip sites whose wp-config.php is a symlink or not owned by the account. Test: a symlinked wp-config.php fixture is skipped by the scan and left unchanged by EnsureRealCron.

## F8. A FIFO in a site blocks the CMS scan forever ("a CMS scan is already running" until restart)
- Severity: MEDIUM
- Kind: failure-mode / security
- Confidence: HIGH
- Where: agent/internal/cms/inventory.go:24-31 (readHead), latest.go:163-175 (md5File), called from Plugins/Themes/VerifyCore
- Scenario: The account runs `mkfifo wp-content/plugins/x/a.php`, or replaces a core file such as `wp-admin/about.php` with a FIFO or a symlink to one. `os.Open` for reading blocks until a writer appears, and the 6 h context does not interrupt the open. The scan goroutine never returns and `m.running` stays true. Every later scheduled or manual CMS scan on the server fails, so vulnerability auto-updates and DB scans stop for all accounts.
- Fix: in readHead and md5File, `Lstat` first and skip anything that is not a regular file. Open with `O_NONBLOCK|O_NOFOLLOW` (the same helper as F2). Test: a FIFO fixture in plugins/ and wp-admin/ lets `Plugins`/`VerifyCore` return.

## F9. A CAPTCHA listener that fails to bind is never retried; banned visitors get "connection refused"
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: HIGH
- Where: agent/internal/captcha/captcha.go:119-145
- Scenario: `sync` sets `s.running` before the goroutines call `ListenAndServe`. If binding 7780 or 7743 fails (port taken, a transient error), the error is only logged and `running[0] != nil` stays true, so later syncs return early. The firewall keeps NAT-redirecting every banned or IPDB address to a port nobody listens on. Real people behind a shared or listed address can no longer unblock themselves until the agent restarts or the ports change. If only the HTTPS listener fails, it is never noticed.
- Fix: bind with `net.Listen` inside `sync` and keep the server only if both binds succeed (`srv.Serve(ln)`). Otherwise leave `running` nil so the next 15 s tick retries, and report the error in the status/health check. Test: occupy the port, call sync, free the port, call sync again, and the server is listening.

## F10. Concurrent map writes in the process monitor (rkhunter "run now" while the monitor loop runs) can crash the agent
- Severity: MEDIUM
- Kind: bug
- Confidence: HIGH (race exists); probability is low
- Where: agent/internal/monitor/monitor.go:129-143 (once writes m.processed), :812-833 (RunRootkit from core.go:1345), :66-86 (init)
- Scenario: The portal's rootkit "run now" calls `RunRootkit` on a handler goroutine. When rkhunter finishes, it calls `m.once` and writes `m.processed`, while the `Run` goroutine's `CheckProcesses`/`CheckCron` also write `m.processed`/`m.killed`/`m.cpu`. Go aborts with "concurrent map writes" and the agent exits. `Status()`/`EnableCron` call `init()` concurrently as well, and the weekly `maybeRootkit` can run rkhunter at the same time as the manual run.
- Fix: add a `sync.Mutex` to Monitor that covers `once`, `init` and the maps, plus an atomic flag so only one rkhunter runs at a time. Test: run `RunRootkit` and `CheckProcesses` in parallel under `-race`.

## F11. The process monitor never kills a later process that reuses a killed PID, and may kill a recycled PID
- Severity: LOW
- Kind: bug / leak
- Confidence: HIGH
- Where: agent/internal/monitor/monitor.go:604-612 (`m.killed[p.PID]`), 129-143 (`processed`)
- Scenario: `killed` is keyed by PID alone and never pruned. After a miner with PID 4242 is killed, a new miner that later gets PID 4242 is skipped (`!m.killed[p.PID]`) and keeps running. The kill is also sent by number some time after /proc was read. If the PID was reused in between, another process gets SIGKILL, possibly one owned by root. `processed` grows by one entry per distinct command line forever, and its kv rows too.
- Fix: key `killed` by `cpuKey{pid,start}` and prune it like `m.cpu`. Before the kill, re-read `/proc/PID/stat` and compare the start time, or use `pidfd_open` + `pidfd_send_signal`. Bound `processed`.

## F12. The weekly rkhunter run stops process and cron monitoring for up to an hour
- Severity: LOW
- Kind: failure-mode
- Confidence: HIGH
- Where: agent/internal/monitor/monitor.go:88-110, 802-835
- Scenario: `maybeRootkit` runs rkhunter synchronously inside the 1-minute loop, with a timeout of 1 h. For that whole run no miner is killed and no cron line is disabled.
- Fix: run rkhunter in its own goroutine, guarded by a once-at-a-time flag (see F10).

## F13. The CAPTCHA "done" page cleans the way back with a weaker check than safeBack (backslash)
- Severity: LOW
- Kind: duplicate / security
- Confidence: MEDIUM
- Where: agent/internal/captcha/captcha.go:419-426 vs safeBack :469-475; page() :551-557
- Scenario: `verify` accepts any `back` that starts with "/" but not "//", so `/\evil.com` passes and goes into `<meta http-equiv=refresh content="3;url=/\evil.com">`. `content` is not a URL attribute for html/template, so the backslash is not escaped, and browsers read `/\` as `//`, which leads to evil.com. It is only reachable with a crafted POST (browsers turn a typed `\` into `/`), so the impact is low. The two sanitizers have drifted apart.
- Fix: use `safeBack` in `verify` and `page` too (one function for every way back).

## F14. CAPTCHA attempt limiter: a flood of addresses clears every counter
- Severity: LOW
- Kind: security
- Confidence: HIGH
- Where: agent/internal/captcha/captcha.go:186-205
- Scenario: When `attempts` passes 10,000 keys, it is replaced with a map that holds only the current address, which resets the 10-per-10-minutes limit for all addresses. An IPv6 attacker with a /64 can reset it whenever it wants and then keep guessing image digits for its own address (the image id is not single-use within its 5 minutes).
- Fix: count by /64 for IPv6, drop expired entries instead of clearing the whole map, and make a challenge id single-use after a wrong answer.

## F15. CertStore holds one mutex across disk reads and index rebuilds: TLS handshakes are serialized
- Severity: LOW
- Kind: failure-mode
- Confidence: HIGH
- Where: agent/internal/captcha/certs.go:193-274
- Scenario: Every handshake with an unknown SNI (a random-name flood, or 10k domains after a cache reset) does up to 4 file opens under `c.mu`. Every 10 minutes one of them rebuilds the index by reading and parsing every certificate directory, which can take seconds on large servers. All other handshakes wait for it.
- Fix: rebuild the index in the background (copy-on-write map behind an `atomic.Pointer`), do file IO outside the lock, and cache negative results with a bounded LRU.

## F16. The extra notification address is not validated: header injection into `sendmail -t`
- Severity: LOW
- Kind: security
- Confidence: HIGH
- Where: agent/internal/settings/settings.go:860-996 (no check of `notifications.extra_email`); notify/notify.go:128-129; notify/mail.go:462
- Scenario: `extra_email = "a@x.com\r\nBcc: someone@else"` reaches `h("To", to)` as is. `sendmail -t` then also sends every server alert to the hidden Bcc address. The admin address goes through `mail.ParseAddress`, but the extra address does not.
- Fix: in `validate`, require `mail.ParseAddress` for `email`/`extra_email`/`from`, and in `buildMessage` write `To` from the parsed `a.Address` only.

## F17. OSM per-sender maps never shrink; "recipients in the last 24 hours" counts since the first message
- Severity: LOW
- Kind: leak / bug
- Confidence: HIGH
- Where: agent/internal/mail/osm.go:262-271, 300-304 (`counts`, `flagged`); osmstats.go:64 (`rcpts`)
- Scenario: `counts[k]` and `flagged[k]` are created for every sender key and never deleted. With F6's rotating senders, that is one entry per message forever. `senderStat.rcpts` is cumulative and never trimmed with the hourly buckets, so a sender that keeps sending shows ever-growing "recipients in 24h".
- Fix: prune `counts`/`flagged` entries older than an hour in `prune`, and keep recipients per hour bucket like `hours`.

## F18. Audit report sends full cron command lines (often with passwords and tokens) to the portal
- Severity: LOW
- Kind: security (secret leak)
- Confidence: HIGH
- Where: agent/internal/audit/audit.go:702-718
- Scenario: Items for cron lines with no timeout or listed twice put the whole line in `Detail`, e.g. `curl -u user:password ...` or `wget "https://.../cron?key=SECRET"`. The report goes into the portal database and UI. The same package's key finder masks secrets, but this check does not.
- Fix: mask URL credentials, query values and `-u/-p` arguments before putting the line in `Detail`, or show only the program and the folder.

## F19. Website-address CAPTCHA: every withdrawn pass starts its own WAF apply, and every pass rewrites the whole state
- Severity: LOW
- Kind: failure-mode
- Confidence: HIGH
- Where: agent/internal/core/central.go:217-228 (onPassCookie: `go a.WAF.Apply()` each time); captcha/sitepasses.go:219-226, 265-284
- Scenario: Holders of one solved cookie sending it from several addresses withdraw up to 8 slots per 2 minutes. Each withdrawal starts a separate WAF apply (a LiteSpeed graceful restart) with no coalescing. `Give` marshals and saves the full pass state (up to 100k entries, several MB) to SQLite on every pass.
- Fix: send withdrawals through the existing coalesced apply (`centralPassFor`-style generation counter), and save only the delta or on a timer.

## F20. The brand name is cut at 60 bytes, which can split a UTF-8 character
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: agent/internal/settings/settings.go:780-782
- Scenario: An Urdu or Arabic brand longer than 60 bytes is cut in the middle of a rune. The account owners' emails then carry invalid UTF-8 in the From display name and the HTML.
- Fix: truncate by runes (`[]rune`) or with `utf8.ValidString` backtracking.

## F21. DB "Restore" ignores which database the value came from and overwrites later edits
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: agent/internal/cms/dbclean.go:181-211
- Scenario: `restoreOne` reads the current wp-config.php and writes `old_value` with `WHERE key = ?` only. It does not compare `db_name` with the backup's database, and it has no condition on the current value. If the site now points at another database (staging clone, migration), the saved row (the malware) is written there, and an edit the owner made after the clean is silently overwritten.
- Fix: refuse when `cfg.Name != backup.db_name`, and update only when the current value equals the cleaned value (store it in the backup row).

---

## Area summary

**Read in full:** captcha/ (captcha.go, site.go, sitepasses.go, passthrough.go, certs.go, pow.go, image.go), settings/settings.go, mail/ (eximguard, eximrbl, osm, osmstats, greylist), notify/ (notify, mail, template escaping), audit/audit.go, monitor/monitor.go, panel/panel.go + ui.html (escaping), and the CMS code: cms.go, dbscan (config/open), dbclean, discover, inventory, latest (verify), vulns (cron/auto-actions). sysinfo and layout were skimmed for root-unsafe operations and races; nothing material was found there. For context I also read the core glue (central.go handlers, core.go wiring, extras.go mailOwner, gate.go, audit runner).

**Checks run:** `go vet` and `go test` on the area packages pass. Scratch programs reproduced F1 (path forwarded with `..`), F2 (fatal out-of-memory on a 1 TB sparse file) and F3/F4 (json slice aliasing and merge).

**Overall health:** Templates are escaped correctly (html/template, and `esc()` in the panel UI). The ticket and pass-cookie logic is careful: single-use tickets bound to the address, IPv6 counted per /64, `postMessage` origin checked, strict CSP. Exim filter text is static, so no config injection is possible. Commands run with exec argv, never a shell.

**Riskiest spots:**
1. The machine-file passthrough proxy in the CAPTCHA server (F1): a real ban bypass.
2. Every place the root agent reads or writes files inside customer accounts (cms/, audit/): it follows symlinks, opens FIFOs and reads files with no size limit (F2, F7, F8). One `readUserFile` helper (O_NOFOLLOW, O_NONBLOCK, Fstat regular file, owner check, size cap) would close all three.
3. `settings.Patch`'s shallow copy and in-place JSON merge (F3, F4).
4. The OSM's choice of which account it acts on and counts (F5, F6).
