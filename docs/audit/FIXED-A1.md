# Fixed: A1 (agent runtime), plus agent-side A10 findings

Branch `worktree-agent-a07dca08ecad80750`. F1 and F2 of A1 belong to another fixer.

## A1

- F1 | skipped: assigned to another fixer
- F2 | skipped: assigned to another fixer
- F3 | partly fixed d38bd87 | test TestUpdateRefusesDowngradeAndCleartext, TestCheckPortalURLRefusesHTTPAndRedirects. Updates now refuse a lower version than the running agent, refuse a portal address that is not https, refuse a portal whose certificate is not checked (`--insecure`), and follow no redirects. `portal.move` takes https only, checks the new address with full TLS checks, follows no redirect, and clears `insecure_tls` when it moves. Left: release signing needs the owner's signing key (see "What the owner must do for signing" below).
- F4 | fixed d38bd87 | test TestUpdateKeepsPreviousAndRollsBack. The replaced binary is kept as `xpguard-agent.prev`, and an `xpguard-agent.update` marker counts how many times the new build starts. `run` checks the marker first. After 3 starts that neither reached the portal nor ran for 10 minutes, it puts `.prev` back and exits with code 3, so systemd starts the old build. Not done: the installer backstop (`StartLimitIntervalSec=0`) is in installer/install.sh, which is outside this scope. systemd's default limit (5 starts in 10 s) is not reached with `RestartSec=5`.
- F5 | fixed 5440660 | test TestHandleLimits, TestHandlerPanicIsAnError. A panic in a portal or local-socket handler now becomes an "internal error" result and its stack is logged. At most 16 portal commands run at once; beyond that the answer is "busy". These heavy actions run one at a time: learning.sample, findings.recheck, domainrep.check, db.clean, monitor.rootkit, clamav.reload.
- F6 | fixed 5440660 | test TestHandleLimits. The agent now has a per-action deadline table that matches the portal's ACTIONS: monitor.rootkit 60 min, clamav.reload 25 min, cms.update 11 min, everything else 10 min.
- F7 | fixed d38bd87 | test TestUpdateSlowDownload. The update download has no fixed total timeout. It stops only when nothing arrives for 60 s, or at the command deadline. A failed download is tried 3 times, 5-30 s apart. Staggering updates from the portal side is not done (portal code is out of scope).
- F8 | fixed e5a37b3 | test TestEverySecretFieldIsMasked. `reputation.spamhaus_dqs_key` is now masked and listed in `secretFields`, so a masked value sent back keeps the stored key. The test walks every settings field whose name contains key, token, secret, password or webhook. The CLI export reads `settings.get`, so it is masked too.
- F9 | fixed b6c2ae0 | test TestWPCLIRefusesOptionArguments. A slug must match `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`. `WPCLI` refuses any argument that starts with `-` except `--force`, `--skip-content` and `--version=<version>`. This also covers plugin directory names that come from customer files (automatic deactivate and update).
- F10 | fixed 83a203d | test TestSummaryCountsCached. The table counts, the cPanel userdata read and the reputation lookups behind the metrics summary are cached for 5 minutes and refreshed in the background. Problems, firewall stats and realtime watches stay live. No new index was added for `waf_events`.
- F11 | fixed dbf53a6 | test TestSiteScoresUsePathIndex. The per-site counts use `path >= 'dir/' AND path < 'dir0'`, which uses the `findings_path` index. The test checks the query plan and that the sibling folder `public_html2` is not counted.
- F12 | fixed eb9f9cf | test TestRotateLog. The agent checks the file behind its stderr every 10 minutes. Above 50 MB it copies the file to `agent.log.1` and truncates it, which works with systemd's `append:`. A logrotate file from the installer would be an alternative, but the installer is out of scope.
- F13 | fixed 55ffa2b | test TestAdminClearStandsForUntrustedSignature. `clearFinding` now saves the verdict with `Source: admin`. The agent never uploads this row; the portal records its own fleet-wide correction.
- F14 | fixed 8d8da91 | test TestCrawlerCheckBusyAndBounded. An address is marked seen only after a check slot is taken. The map is capped at 20000 entries; when it is still full after removing entries older than 24 h, arbitrary entries are removed. Keying by IPv6 /64 was not done, because each address is verified on its own.
- F15 | fixed 351cb7a | test TestPruneOldGrowingTables. `pruneOld` now also deletes: sent `ipdb_hits` older than retention, findings with status `cleared`, old `db_clean_backup` rows, old `ipdb_country` days, and `ai_verdicts` older than max(retention, 180 days) that no finding names (admin and fleet verdicts are kept). `KeepDays <= 0` cannot happen: normalize already sets 60. Rows dropped from `ai_verdicts` stay in the in-memory cleared set until the agent restarts.
- F16 | fixed b175c01 | test TestLastMonth, TestRecordPrunesEvery512th. "Last month" is now computed from the first day of the current month. WAF events are kept at least 32 days, both in `waf.record` and in `pruneOld`. The 32-day rule also applies to `ipdb_country`.
- F17 | fixed b175c01 | test TestRecordPrunesEvery512th. Pruning uses the INSERT's `LastInsertId`, so it runs every 512th insert. One line changed in agent/internal/waf/waf.go, which is outside the listed files.
- F18 | fixed b041081 | test TestKeepaliveNoticesDeadPortal. The agent pings every 45 s with a 20 s timeout, and a failed ping ends the session. After a failure the connection is closed at once instead of waiting for a close handshake the dead peer never answers.
- F19 | fixed 619054d | test TestSettingsHistoryOnlyForSavedChanges. A history row is written only after `Patch` succeeds. "ignore", `waf.rule` and the portal's own-rules switch now go through `patchSettings`, so they are in the history. "ignore" no longer adds a path that is already listed.
- F20 | fixed adb4538 | test TestOverlongLineDropped. Lines longer than 1 MB are dropped, including the rest of the line up to its newline, instead of growing in memory.

## A10 (agent side)

- F1 | fixed 48f502b | test TestPatchDoesNotWriteIntoSharedLists (settings), TestSameLengthListChangeIsApplied (core). `Patch` now merges the patch into the current settings as JSON: objects merge key by key, lists and values are replaced whole, and a null leaves a section as it is. The result is decoded into a fresh `Settings`, and `st.cur` is set only after validate and save succeed.
- F3 | fixed e5a37b3 | same fix and test as A1 F8.
- F4 | fixed 5440660 | test TestHandleLimits, TestRootkitCutShortIsAnError. Deadline table as in A1 F6. An rkhunter run killed by its deadline is now an error: the warnings seen so far are recorded, but it is not stored as a "0 warnings" result. One small change in agent/internal/monitor/monitor.go, outside the listed files.
- F5 | partly fixed 5440660 | test TestHandleLimits. A result over 3.5 MB becomes the error "result too large" instead of a frame that drops the connection. Left: paginating `fw.list` needs portal and web changes (out of scope).
- F6 | partly fixed 31f5b01 | test TestWhitelistAddresses. `waf.whitelist_ips` and `osm.whitelist_ips` refuse ranges wider than /8 (IPv4) or /16 (IPv6) and invalid octets, and store `::ffff:a.b.c.d` as IPv4 and ranges as their network. A server that already has such a wide range must remove it at its next save, because the save is refused until then. Left: one shared helper for firewall, waf and hostfw, and the TypeScript copies (outside this scope).
- F7 | left: needs an owner decision on which source of the DQS and Safe Browsing keys is kept.
- F8 | left: dead-code cleanup spread across many packages and the web. It is not a bug, and removing it is beyond a minimal fix.
- F2, F9 | not agent-side (portal and web).

## What the owner must do for signing (A1 F3)

1. Make an Ed25519 key pair on an offline machine (for example `openssl genpkey -algorithm ed25519 -out xpguard-release.key` and `openssl pkey -in xpguard-release.key -pubout`). The private key never goes into the repository, the portal or a server.
2. Give the public key (32 bytes, base64) to the next fixer. It is embedded in the agent (for example `updater.ReleaseKey`).
3. For each release, sign `version|arch|sha256` of each `xpguard-agent-linux-<arch>` with the private key, and publish the signature as `xpguard-agent-linux-<arch>.sig` next to the `.sha256` in the portal's downloads.
4. The agent then refuses any binary without a valid signature, and refuses a lower version unless a signed rollback flag is present. `portal.move` can require a signature by the same key in the same way.

Until then, a compromised portal (or anyone who can change the files the portal serves) can still push a binary that claims a newer version. What this branch adds narrows the path: https with verified TLS, no redirects, no downgrade as reported by the new binary, and a rollback when the new build fails to start.

## Checks

- `go vet ./...` is clean.
- These package tests pass: core, settings, client, updater, local, logtail, monitor, store, identity, cmd, cms, and the waf tests I added.
- When all those packages run in one `go test` call, TestPanelSocketIsolatesAccounts and TestRestoredFileIsNotFlaggedAgain sometimes fail: their fixed scan-wait times run out under CPU load. They pass when the core package runs on its own.
