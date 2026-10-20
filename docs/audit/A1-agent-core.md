# A1: agent runtime (core, cmd, client, protocol, updater, identity, config, store, local, prio, logtail, version)

## F1. A cPanel user (or PHP malware running as that user) can restore its own quarantined malware and whitelist the hash for the whole server
- Severity: HIGH
- Kind: security
- Confidence: HIGH
- Where: agent/internal/core/panel.go:207-240 (user `finding.action` "restore"), agent/internal/core/core.go:2021-2034 (`restoreFinding`), agent/internal/local/local.go:91 (socket mode 0666), agent/internal/ai/ai.go:397-412 (admin source beats the untrusted-signature guard), agent/internal/core/core.go:131 (`Scanner.Cleared = ai.IsCleared`)
- Scenario: the local socket accepts every uid. The user command table gives any cPanel account "restore" on findings under its home. `restoreFinding` always saves `Verdict{Clean, Confidence 100, Source: ai.SourceAdmin}` for the file's SHA-256. `loadCleared` treats `source='admin'` as cleared even for "untrusted" signatures, and the scanner skips cleared hashes on every account. So a web shell (PHP runs as the account uid; there is no CageFS on plain Apache/PHP-FPM) or a hostile customer can call `{"action":"finding.action","params":{"ids":[N],"action":"restore"}}`. The shell comes back, and the same malware content is never flagged again anywhere on the server: other accounts, realtime and scheduled scans included.
- Fix: in `userHandlers`, keep "restore" for panel users but call `Scanner.Restore` without saving any verdict. Better still, refuse restore for untrusted signatures (`ai.Untrusted`) and leave it to root/portal. Make `restoreFinding` take an `admin bool` and write a `SourceAdmin` verdict only from the root/portal path. Regression test: a user-table restore leaves `ai.IsCleared(sha)` false.

## F2. Restore, delete, quarantine and disable follow symlinked parent directories as root (arbitrary file create/delete)
- Severity: HIGH
- Kind: security
- Confidence: HIGH
- Where: agent/internal/scanner/actions.go:69-177 (`Quarantine`, `Disable`, `Restore`, `Delete` use `r.path` with plain `os.Rename/Remove/Chmod/Lchown`), reached from agent/internal/core/core.go:732-779, 1200-1265 and agent/internal/core/panel.go:79-88, 57-68 (`owns`/`within`)
- Scenario: (a) User panel: the finding `/home/u/public_html/x` is quarantined. The user replaces `public_html` with a symlink to a root directory (e.g. `/etc/<dir>`) in which `x` does not exist. `within()` calls `EvalSymlinks`, which fails because the final component is missing, and falls back to the unresolved path. That path is still "inside home", so the check passes. `Restore` then does `Lstat` (absent), `MkdirAll` and `moveFile(qpath, r.path)` through the symlink. Root creates a file with attacker-controlled content in a root-owned directory, then `Lchown`s it to the user and `Chmod`s it to the original mode. (b) Portal admin: restore, delete and "ignore" have no ownership or symlink check at all. If a detected file is named `shadow` (or any root file name) and its parent is swapped for a symlink to `/etc`, an admin "delete" runs `os.Remove("/etc/shadow")` as root. "quarantine" moves the root file into quarantine (DoS). The window between `owns()` and the action is also a plain TOCTOU race.
- Fix: do every file action on a finding relative to an `O_PATH|O_DIRECTORY` handle of the account home, opened with `unix.Openat2(..., RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)`. Use `unlinkat`, `renameat` and `fchownat` on the parent dirfd. Fall back to a walk that `Lstat`s each component and refuses symlinks, and re-check after opening. Apply this in `scanner` for every caller (portal, panel, AI, retention). Regression test: a tmp tree whose parent is swapped for a symlink makes restore, delete and quarantine fail.

## F3. Self-update and portal move trust the portal completely: no code signature, downgrades allowed, http allowed, permanent redirect
- Severity: HIGH
- Kind: security
- Confidence: HIGH
- Where: agent/internal/updater/updater.go:24-76, agent/internal/core/core.go:1768-1841 (`agent.update`, `portal.move`, `checkPortalURL`), agent/internal/client/client.go:33-39, agent/internal/config/config.go:232
- Scenario: the binary and its `.sha256` come from the same origin, and `expectSHA` is also sent by that origin. Only TLS protects them, and there is no TLS at all when the agent is enrolled with `--insecure` or an `http://` URL. Consequences: (1) one portal compromise means root on every server; (2) the portal can push an older, vulnerable build because nothing compares versions; (3) `portal.move` accepts `http://` and any host that answers `/api/health {"ok":true}`, so a compromised portal can move the whole fleet to an attacker host or downgrade it to cleartext. The move is saved in agent.json and outlives the portal's recovery. Combined with (1), any network MITM then gets root.
- Fix: embed an Ed25519 release public key in the agent. Verify a detached signature over `version|arch|sha256` before rename, and refuse a lower version unless a signed rollback flag is set. In `checkPortalURL`, require https (http only when the current URL is already http) and keep `InsecureTLS` from carrying over silently. Ideally, accept `portal.move` only with a signature by the same release key.

## F4. No rollback after a self-update: a build that passes `version` but fails at `run` crash-loops forever and cannot be fixed remotely
- Severity: HIGH
- Kind: failure-mode
- Confidence: HIGH
- Where: agent/internal/updater/updater.go:60-75, agent/cmd/xpguard-agent/main.go:249, installer/install.sh:222-226 (`Restart=on-failure`, `RestartSec=5`, no StartLimit)
- Scenario: the only check is `tmp version`. A new build that panics in `core.New`, in a store migration or in `Start` on some OS/panel combination replaces the binary, exits 3 and restarts every 5 s indefinitely. The old binary is gone (renamed over), and the agent never reconnects, so the portal cannot push a fix. Scanner, realtime and WAF log processing stay down on every affected server until someone logs in over SSH. Auto-update pushes this to the whole fleet on reconnect.
- Fix: keep `self+".prev"` and write an "update pending" marker before the exit. The new binary clears the marker after its first successful portal handshake (or after N minutes up). At startup, if the marker shows more than 3 failed starts, rename `.prev` back and exit, so systemd restarts the old build. Add `StartLimitIntervalSec=0` or an OnFailure unit as a backstop.

## F5. Any panic in a command handler kills the root daemon; handler concurrency is unbounded
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: HIGH
- Where: agent/internal/client/client.go:304-306, 333-353; agent/internal/local/local.go:131-184; no `recover()` anywhere in the agent
- Scenario: each portal command runs in `go s.handle(...)` with no `recover`. A nil dereference or index panic in any of about 100 handlers (or in the modules they call) panics the whole process: firewall loops, realtime scanner and WAF log reader all stop until systemd restarts it. Also, the portal's 30 s timeout removes the request from `pending`, so its `MAX_PENDING` cap does not limit the agent. Repeated clicks or mass operations start unlimited parallel heavy handlers (`learning.sample`, `findings.recheck`, `domainrep.check`, `db.clean`), each allowed to run 10 minutes.
- Fix: in `Session.handle` and `local.Server.ServeHTTP`, `defer func(){ if r := recover(); r != nil { log stack; res.Error = "internal error" } }()`. Add a semaphore (e.g. 8 concurrent handlers, with a busy error) and a per-action single-flight for the heavy actions.

## F6. Agent cuts every command at 10 minutes; the portal allows up to 60
- Severity: MEDIUM
- Kind: contract
- Confidence: HIGH
- Where: agent/internal/client/client.go:340 (`context.WithTimeout(ctx, 10*time.Minute)`), server/src/routes/agent-cmd.ts (`monitor.rootkit` 3_600_000, `clamav.reload` 1_500_000, `cms.update` 660_000)
- Scenario: `monitor.rootkit` on a large server and `clamav.reload` (whose `reloadClam(ctx)` downloads with a 20-minute sub-context) are cancelled by the agent at 10 minutes. The portal shows them as failed or partial, although its own timeout says they may take longer.
- Fix: let the portal send a `timeout_ms` in the envelope (capped on the agent), or keep a per-action timeout table on the agent that matches `ACTIONS`. Run long jobs detached and return "started", as `audit.run` does.

## F7. Binary download uses a 30-second total HTTP timeout, and every agent updates at once after a portal deploy
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: HIGH
- Where: agent/internal/core/core.go:1775 (`client.HTTPClient(...)`, `Timeout: 30s`), agent/internal/updater/updater.go:51, server/src/routes/agent.ts:46-58 (auto-update 3 s after each connect)
- Scenario: `http.Client.Timeout` covers the whole body read. After a portal release, about 300 agents reconnect within seconds and each downloads a binary of tens of MB from the same host. Throughput per agent drops and many downloads exceed 30 s, so the updates fail. They are retried only at the next reconnect, which may be days later, and the fleet stays mixed-version.
- Fix: use a client without a total timeout for the download: a context deadline of a few minutes plus a progress/idle timeout. On failure, retry from the agent with jittered backoff (or let the portal stagger updates).

## F8. Spamhaus DQS key is returned in clear to every portal viewer and written by `xgcli config --export`
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: agent/internal/core/core.go:1847-1875 (`secretFields`/`masked` omit `reputation.spamhaus_dqs_key`), agent/internal/settings/settings.go:236, web/src/pages/Settings.tsx:787, agent/cmd/xpguard-agent/cli.go:1681-1697
- Scenario: `settings.get` (portal role "viewer") returns the server's own DQS key in full. The CLI export, which documents that "exported settings never contain secrets", writes it to a file.
- Fix: add `{"reputation","spamhaus_dqs_key"}` to `secretFields` and to `masked` (`keepSecrets` then preserves it on save). Make the Settings page show the masked value. Add a test that runs every `json:"…key|token|secret|password|webhook"` field through `masked`.

## F9. `cms.update` slug allows wp-cli option injection (`--exec=` PHP as the site owner)
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: agent/internal/core/core.go:1570-1584 → agent/internal/cms/cms.go:555-584
- Scenario: the slug filter rejects only ` /\;&|$\``, and `WPCLI` rejects only `\n;&|$\``. A slug like `--exec=…php code…` (or `--require=/home/x/file.php`) passes both checks and becomes an argument to `wp plugin update`. wp-cli runs it as PHP under the site owner. Any portal user with the admin role on that server (not necessarily someone with shell access) gets code execution, against the "no generic shell command" design.
- Fix: validate the slug with `^[a-z0-9][a-z0-9._-]{0,99}$` and insert `--` before positional arguments. In `WPCLI`, reject any argument that starts with `-` unless it is from a fixed allow-list of flags.

## F10. Every metrics sample (60 s, or 5 s in live mode) runs full-table counts and reads every cPanel userdata file, holding the only DB connection
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: HIGH
- Where: agent/internal/client/client.go:275-296, agent/internal/core/core.go:505-570 (`SecuritySummary` → `serverCard`, `dailyCounts`, `Scanner.Stats`, `ServiceHealth`, `cms.CPanelDocroots`), agent/internal/store/store.go:325 (`SetMaxOpenConns(1)`)
- Scenario: on a server with 10k domains and about 1M `waf_events` (30 days), each sample runs `count(*) … action LIKE 'Access denied%'` over the whole table, two `findings` counts, the 14-day daily queries, and opens and parses about 10k `/var/cpanel/userdata/*/*` files. In live mode (the portal's server page) this repeats every 5 s. With one pooled connection, WAF event inserts, realtime finding records and IPDB hit writes queue behind these reads, and `database/sql` waits with no timeout.
- Fix: compute the card in a background goroutine at most every 5–10 minutes and cache it in memory. Keep running counters, or use indexed queries (`waf_events(category, at)`, store the "denied" flag as a column). Cache `CPanelDocroots` with an mtime check on `/var/cpanel/userdata`.

## F11. `siteScores` runs two unindexed full scans of `findings` per website
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: HIGH
- Where: agent/internal/core/score.go:71-82 (also used by monthly.go:68, panel.go:119, report emails)
- Scenario: `substr(path,1,?) = ?` cannot use `findings_path`. With 10k sites and 100k findings that is 20k table scans, about 2·10⁹ row reads, for `sites.scores`, `report.monthly` (60 s portal timeout) and every monthly email run, all on the single connection.
- Fix: one grouped query, or a range predicate `path >= prefix AND path < prefix||x'ff'` that uses the index. Better, load open/removed counts per site in one pass.

## F12. agent.log is never rotated
- Severity: MEDIUM
- Kind: leak
- Confidence: HIGH
- Where: installer/install.sh:227-228 (`StandardOutput=append:$LOG_DIR/agent.log`); no logrotate entry and no size cap in the agent
- Scenario: Info lines for every AI verdict, finding, WAF reload and so on accumulate over months until /opt fills up. A full disk then breaks SQLite writes, quarantine moves and the update temp file.
- Fix: ship `/etc/logrotate.d/xpguard` with `copytruncate` (needed with `append:`), or log to journald, or make the agent cap and rotate its own file.

## F13. An administrator's "clear" (false positive) is not honoured for untrusted signatures, but "restore" is
- Severity: MEDIUM
- Kind: bug
- Confidence: MEDIUM
- Where: agent/internal/core/core.go:2037-2050 (`clearFinding` saves `Source: "ai"`), agent/internal/ai/ai.go:400-412, 446-448
- Scenario: for a signature in `untrustedSignatures`, `noteCleared` and `loadCleared` ignore verdicts whose source is not `admin`. The admin's explicit "clear" is therefore dropped, and the next scan re-detects and re-quarantines the file, breaking the site again. "Restore", by contrast, stores `SourceAdmin` and sticks. This is the opposite of the documented intent ("stays flagged unless an administrator cleared it"). If source "ai" is required for fleet sharing, the local decision still has to be admin-strength.
- Fix: store the local verdict with `SourceAdmin` (keep a separate record or flag for what is shared with the portal). Test: clearing an untrusted-signature finding keeps the hash cleared after `loadCleared`.

## F14. Crawler verification marks addresses "seen" even when it is too busy to check them, and the seen map is unbounded
- Severity: MEDIUM
- Kind: bug
- Confidence: HIGH
- Where: agent/internal/core/crawlers.go:237-273
- Scenario: (1) When the 2-slot semaphore is full, the function returns after `crawlerSeen[ip] = now`. The comment says the address "is checked on a later block", but it is skipped for 24 h, so a real crawler arriving during a burst stays blocked for a day. (2) Once the map passes 20000 entries, only entries older than 24 h are deleted. A bot wave rotating IPv6 addresses adds millions of entries per day (hundreds of MB).
- Fix: set `crawlerSeen[ip]` only after acquiring the semaphore (or delete it on the busy path). Use a size-capped LRU keyed by IPv4 or IPv6 /64.

## F15. Several tables (and one in-memory set) grow forever
- Severity: LOW
- Kind: leak
- Confidence: HIGH
- Where: agent/internal/core/extras.go:527-560 (`pruneOld`), agent/internal/store/store.go (tables `ipdb_hits`, `ai_verdicts`, `db_clean_backup`, `ipdb_country`), agent/internal/ai/ai.go:383-460 (`cleared.set` cache)
- Scenario: `ipdb_hits` gets one row per distinct IPDB entry ever matched, and the list changes daily. `ai_verdicts` gets one row per hash ever judged, and its "clean" subset is kept in memory. `db_clean_backup` and findings with status `cleared` are never pruned. `KeepDays <= 0` disables all pruning, including quarantine.
- Fix: in `pruneOld`, delete `ipdb_hits` with `last_seen < cut AND pending = 0`, `ai_verdicts` not referenced by any finding and older than N days (except `source='admin'`), `db_clean_backup` older than retention, and include `cleared` in the findings statuses. Treat `KeepDays <= 0` as a floor (e.g. 365) for the log tables.

## F16. Monthly report: wrong default month on the 29th–31st, and WAF counts cover only 30 days
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: agent/internal/core/monthly.go:147 (`time.Now().AddDate(0,-1,0)`), agent/internal/waf/waf.go:1073-1075 (30-day prune)
- Scenario: on 31 March, `AddDate(0,-1,0)` gives 3 March, so "last month" reports March (partial) instead of February. On the 1st at 08:00, last month's WAF events older than 30 days have already been deleted, so days 1–2 of a 31-day month count zero attacks. Asking for older months shows 0 attacks and bots.
- Fix: compute the first day of the current month and then `AddDate(0,-1,0)`. Keep WAF events for at least 32 days, or store monthly aggregates before pruning.

## F17. WAF event insert runs the 30-day DELETE on every insert
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: agent/internal/waf/waf.go:1069-1075
- Scenario: `e.ID` is never set before `record()` (always 0), so `e.ID%512 == 0` is always true. Every WAF hit costs an extra DELETE on the single DB connection, which hurts during an attack flood.
- Fix: use the `LastInsertId()` of the INSERT, or an atomic counter.

## F18. No keepalive on the portal websocket
- Severity: LOW
- Kind: failure-mode
- Confidence: MEDIUM
- Where: agent/internal/client/client.go:274-318
- Scenario: after a NAT or network drop without a FIN, reads block forever. Metrics writes go into the kernel buffer until TCP gives up (tcp_retries2, about 15 min), so the server shows offline and commands fail for about 15 minutes before the agent reconnects.
- Fix: run `conn.Ping(ctx)` with a 20 s timeout every 30–60 s in the metrics goroutine, and treat a failure as a disconnect.

## F19. Settings changes that bypass history; history written for failed patches
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: agent/internal/core/core.go:762-768 ("ignore" → `Settings.Patch`, appends duplicates to `whitelist_paths`), 1526-1547 (`waf.rule`), agent/internal/core/wafsync.go:297-302, agent/internal/core/core.go:822-829 (`recordSettings` before `Patch` can fail)
- Scenario: whitelist entries added by "ignore", WAF rule switches and the portal's own-rules switch are not in `settings_history`, so "undo last night's change" cannot roll them back. Repeated "ignore" of the same path grows the whitelist with duplicates. A rejected `settings.set` still adds a history row, which pushes real entries out of the 100 kept.
- Fix: route these through `saveSettings` (or call `recordSettings` and dedupe), and record history only after `Patch` succeeds.

## F20. logtail keeps a partial line in memory without a limit
- Severity: LOW
- Kind: leak
- Confidence: MEDIUM
- Where: agent/internal/logtail/logtail.go:338-352
- Scenario: when a followed log has a very long line, or a binary blob with no `\n` (e.g. a ModSecurity audit part that is written incrementally), `partial += chunk` grows by up to 8 MB per 2-second tick until a newline arrives.
- Fix: cap `partial` (e.g. 1 MB) and drop or flush the rest of the line.

## Area summary

Read in full: all of agent/internal/core (non-test files, including core.go, extras.go, central.go, panel.go, hosttrust.go, learning.go, wafsync.go, wafintel.go, mailguard.go, notifications.go, history.go, clamav.go, rbl.go, monthly.go, score.go, report.go, reinfection.go, profile.go, unitmove.go, weights.go, gate.go, spikes.go, crawlers.go, audit.go); agent/cmd/xpguard-agent (main.go, the dispatch and file/HTTP parts of cli.go, ai.go); client, protocol, updater, identity, config, store, local, prio, logtail and version. I followed the core handlers into scanner/actions.go, ai cleared-cache logic, cms.Update/WPCLI and waf.record, and compared the agent action table with server/src/routes/agent-cmd.ts and agents/hub.ts. `go vet` is clean, and the core, store, identity and cmd tests pass. client, updater and local have no tests.

Overall: handler input validation is mostly careful (typed decode, size caps, regexes for message ids and slugs, portal-only actions kept off the local socket, and secrets masked on read with one exception). The riskiest spots:
1. The 0666 local socket's user command set combined with `restoreFinding`'s admin verdict (F1).
2. Root file actions on recorded paths that never pin the directory chain (F2).
3. The update and move path, which has neither authenticity nor rollback (F3, F4).
4. A single SQLite connection shared by hot writers and heavy dashboard/metrics reads (F10, F11).

Agent↔portal action names match. The only contract gap found is the timeouts (F6).
