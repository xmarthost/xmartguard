# A10: agent/portal contract, settings, duplication, dead code

## F1. Settings.Patch writes into shared slice arrays: list edits merge stale fields, firewall/WAF changes are not applied, and a rejected value stays live
- Severity: HIGH
- Kind: bug
- Confidence: HIGH (reproduced with a temporary `go test -overlay` file; nothing in the repo was changed)
- Where: agent/internal/settings/settings.go:597-614 (`Store.Patch`: `next := st.cur; json.Unmarshal(patch, &next)`), agent/internal/core/core.go:822-881 (`saveSettings` / `applySettings` take `job` from `a.Settings.Get()` before the patch), core.go:1908-1918 (`wafChanged` / `fwChanged`), history.go:89-104 (rollback goes through the same path)
- Scenario: `next := st.cur` copies the struct, but every slice in `next` still points at the same backing array as `st.cur` and as every `Get()` copy. When `encoding/json` decodes into a slice that already has capacity, it decodes each element in place. The overlay test showed three effects:
  1. **Stale fields are merged into list elements.** `waf.rule_exclusions` holds `[{rule:942100, domain:"a.example", path:"/x"}]`. Then a list arrives whose first element has no domain or path. This happens when the web removes item 0 or adds an "all websites" exclusion, because `RuleExclusions.tsx:51` sends `domain: undefined`, and the field is also `omitempty` on rollback. The result is `{Rule:942200 Domain:a.example Path:/x}`. An exclusion meant for all sites is silently limited to one site and path, so false positives come back; or a different rule inherits another site's scope. The same happens to `scanner.db_whitelist` elements.
  2. **The "before" snapshot changes with the patch, so nothing is reapplied.** `job` (core.go:825) holds `cur.Firewall` and `cur.WAF`, whose slices share the array that `Patch` overwrites. When a list is edited and keeps the same length or gets shorter, `fwChanged(job.fw, next.Firewall)` and `wafChanged(...)` compare the new values with themselves and return false. Test: blocked_countries `["CN"]` then `["RU"]`; the snapshot read back `[RU]`. As a result the firewall is not rebuilt (CN stays blocked, RU is not blocked), and a changed WAF whitelist_ips, login_urls or trusted_disabled is not written, until some unrelated change forces a reload. The `gateChanged` check over LoginURLs (core.go:864) fails the same way, and so do fleet pushes (`trusted.apply`, `captcha.central`).
  3. **A rejected patch corrupts the live settings.** The patch `{"waf":{"whitelist_ips":["not-an-ip"]}}` fails `validate`, but `st.cur.WAF.WhitelistIPs` now reads `[not-an-ip]`. Every later `settings.set` on that server fails with `invalid IP address "not-an-ip"` (reproduced) until the agent restarts. Meanwhile any WAF or firewall rebuild that reads `Get()` uses the invalid value. Readers that hold a `Get()` copy also race with the write.
- Fix: in `Patch`, merge at the JSON level instead of decoding over the live struct. Marshal `st.cur` to `map[string]map[string]json.RawMessage`, overlay the patch's keys at section and field level (a list in the patch replaces the whole value), then unmarshal the merged document into a zero `Settings`. Only then run normalize and validate, and assign `st.cur` only on success. This gives fresh slices, so the `job` snapshot stays intact and rollback stops merging elements. Regression test in settings_test.go covering all three cases above, plus a core test that a same-length `blocked_countries` change triggers `Firewall.Apply`.

## F2. "Learned exclusions" Accept/Reject buttons always fail: `waf.auto_exclusion` is not in the portal's ACTIONS list
- Severity: HIGH
- Kind: contract
- Confidence: HIGH
- Where: web/src/pages/Settings.tsx:1109 (`agentCall(serverId, 'waf.auto_exclusion', { key, action })`), server/src/routes/agent-cmd.ts:14-109 (ACTIONS has no `waf.auto_exclusion`; `git log -S` shows it was never added), agent/internal/core/core.go:1491 (handler exists)
- Scenario: An admin clicks Accept on a suggested false-positive exclusion (Settings » WAF). The request goes to `POST /api/servers/:id/agent/waf.auto_exclusion` and gets 404 `unknown action`. The project rule is "only an administrator switches one on (Accepted)", so on every server no learned exclusion can be accepted, rejected or forgotten from the portal. MCP `agent_command` cannot do it either, because it also checks ACTIONS.
- Fix: add `'waf.auto_exclusion': { role: 'admin', mutates: true, timeoutMs: 180_000 }` (the handler runs `WAF.Apply`). Add a server test that every action string the web passes to `agentCall` / `useAgent` is a key of ACTIONS. A grep-based test over web/src is enough; this audit's grep found only this one missing action.

## F3. The Spamhaus DQS key is returned unmasked by settings.get (viewers, MCP read tokens)
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: agent/internal/core/core.go:1847-1875 (`secretFields` and `masked()` leave out `reputation.spamhaus_dqs_key`), settings.go:236; read paths: agent-cmd.ts `settings.get` (role viewer), mcp.ts:209 `get_settings`
- Scenario: A server has its own DQS key. Any viewer-role user of the account, and any read-only MCP token (whose output may go to an outside AI assistant), receives the full key in `settings.reputation.spamhaus_dqs_key`. The Safe Browsing key, CAPTCHA secret, SMTP password and the other secrets are masked; this key is not. HANDOFF treats the DQS key as a secret.
- Fix: add `{"reputation","spamhaus_dqs_key"}` to `secretFields` and mask it in `masked()`. `keepSecrets` then keeps the stored key when the masked value comes back. On the web, Settings.tsx:787-835 already only sends a new value the admin typed, so it keeps working. Add a regression test for masking.

## F4. The agent cancels every command after 10 minutes, but the portal waits up to 60 minutes (rootkit check, ClamAV reload, CMS update)
- Severity: MEDIUM
- Kind: contract
- Confidence: HIGH
- Where: agent/internal/client/client.go:339 (`context.WithTimeout(ctx, 10*time.Minute)` for every handler); server/src/routes/agent-cmd.ts: `monitor.rootkit` 3_600_000, `clamav.reload` 1_500_000, `cms.update` 660_000; agent/internal/monitor/monitor.go:804-806 (rkhunter runs under `CommandContext`, and its error is ignored), core/clamav.go:40 (20-minute internal budget)
- Scenario: On a large server rkhunter needs more than 10 minutes. The context is cancelled, rkhunter is killed, its error is discarded, and the warnings counted from partial output (often 0) are reported as success: "0 warnings". A ClamAV download over a slow link is cut at 10 minutes even though the portal and the function itself allow 20-25 minutes. A slow `cms.update` is killed mid-update, which can leave a site half-updated.
- Fix: let the portal send the deadline (for example `timeout_ms` in the command envelope; the agent uses it with an upper bound), or give the agent a per-action deadline table that matches ACTIONS. Report a killed rkhunter as an error (check `cctx.Err()`). Test: a handler with a deadline longer than 10 minutes is not cancelled early.

## F5. Unbounded agent results go over the portal's 4 MB WebSocket limit and drop the whole connection
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: MEDIUM
- Where: server/src/app.ts:92 (`maxPayload: 4 MiB`), agent/internal/core/core.go:959-966 (`fw.list` returns every rule of a kind, with no limit or offset), firewall/firewall.go:258
- Scenario: Mass Operations add 1000 addresses per call, so a server can collect tens of thousands of deny or tempban rules (each JSON rule is about 120-200 bytes, so roughly 25-35k rules reach 4 MB). Opening Firewall » Blacklist then makes the agent send a result frame larger than 4 MB. `ws` closes the socket with 1009, `hub.detach` rejects every pending command for that server (scans, settings saves), and the agent reconnects. The page polls again and the cycle repeats. The server shows as flapping and that list can never be viewed or edited from the portal.
- Fix: paginate `fw.list` (`q`, `limit`, `offset`, `total`, like `fw.events`). In `Session.handle`, marshal the result and, if it is larger than about 3.5 MB, return an error ("result too large; use filters") instead of sending a frame that kills the connection. Test: a handler returning 5 MB produces an error result, not a disconnect.

## F6. IP/CIDR validation is written seven times with different rules: the WAF whitelist accepts 0.0.0.0/0, the firewall refuses it
- Severity: MEDIUM
- Kind: duplicate
- Confidence: HIGH
- Where: Go: firewall/nft.go:559 `ParseAddr` (refuses ranges wider than /8 or /16, rewrites `::ffff:a.b.c.d` to IPv4), settings/settings.go:1074 `validIPorCIDR` and waf/rules.go:1071 `validAddr` (accept /0, keep the v4-mapped form), hostfw/hostfw.go:320 `normAddr` (refuses /0 and loopback). TS: server/src/ipdb/service.ts:50 `parseCidr` (/8 minimum), routes/trusted.ts:11 `validAddr` (/8 minimum), routes/mass.ts:134 `isAddr` (accepts /0), web/src/components/controls.tsx:413 `isIPorCIDR` (regex only; accepts `999.1.1.1`)
- Scenario: `settings.set {"waf":{"whitelist_ips":["0.0.0.0/0"]}}`, or an admin pasting `::/0`, passes validation and the WAF stops inspecting every visitor. The firewall would reject the same entry as "too large". `osm.whitelist_ips` or `waf.whitelist_ips` given as `::ffff:1.2.3.4` is stored as written and never matches, because REMOTE_ADDR and the mail source are plain IPv4. Each copy has to be fixed on its own.
- Fix: one Go helper (move `firewall.ParseAddr` into a small shared package) used by settings validate/normalize (store the canonical form, refuse anything wider than /8 or /16) and by waf/hostfw. One TS helper in server/src (the `parseCidr` rules) used by ipdb, trusted and mass. The web should call it, or at least check the octet ranges. Test with the inputs `0.0.0.0/0`, `::/0`, `::ffff:1.2.3.4` and `999.1.1.1`.

## F7. The same option is stored in two places with silent precedence
- Severity: LOW
- Kind: contract
- Confidence: HIGH
- Where: Spamhaus DQS key: `reputation.spamhaus_dqs_key` (per server) and portal `mail.global.dqs_key` (agent/internal/core/mailguard.go:58). Safe Browsing key: `domain_reputation.safe_browsing_key` and `mail.global.safe_browsing_key` (mailguard.go:69). Trusted services: per-server `firewall.trusted_*` is overwritten by the fleet push `trusted.apply` (hosttrust.go:229). Captcha central: `captcha.central*` is overwritten by `captcha.central`.
- Scenario: The master rotates the portal DQS or Safe Browsing key (for example after a leak). Every server that once had a per-server key keeps the old one, because the server key wins and nothing in the fleet view says which source a server uses. Only `domainrep.get` returns `safe_browsing`; the DQS source is not shown.
- Fix: keep one source. Either remove the per-server key fields, migrating them into the portal key on first sync, or show "server key overrides portal key" with the source in the fleet mail view. Leave the fleet-pushed fields out of per-server write patches.

## F8. Dead handlers, dead functions and leftover options
- Severity: LOW
- Kind: dead-code
- Confidence: HIGH
- Where:
  - Agent handlers the portal never sends: `waf.intel_sync` (core/wafintel.go:211) and `inventory` (cmd/xpguard-agent/main.go:285; inventory arrives as a pushed message). `ipdb.sync` is used (ipdb/service.ts:344).
  - Unreachable Go functions (`deadcode` v0.30.0): clamdb `segOcc`, `pattern.count`; cms `ScanValue`, `ExternalScripts`; core `Agent.centralPass`; hostfw `Host.Sync`; mail `ApplyEximGuard`; ml `Train`; monitor `Judge`, `JudgeCron`; scanner `scanZip`, `ClamDB`, `FeedCounts`, `HashDB.Lookup`, `SignatureCount`, `Realtime.SettingUp`, `Realtime.Scanned`, `WebRoots`, `cpanelDocroots`, `Scanner.ListScans`; trusted `Builtin`; waf `Manager.install`, `MonitoredIDs`, `Manager.PackageStates`. Most are thin wrappers kept only for tests.
  - TS: web/src/timezone.ts `TIME_ZONE_LABEL` is never used. `resetTenancyCache` and `setAbuseIPDBApi` are used only by tests.
  - Settings that normalize forces or rewrites but the web still models: `scanner.delete_symlinks` (always forced false), `waf.custom_bots` and `seo_bots` (folded into `bot_list`), `firewall.allowed_countries` (moved into `ignored_countries`), and `waf.auto_exclusions: 'auto'` (rewritten to `suggest`; still in the web type at Settings.tsx:124).
- Fix: remove the two unused handlers and the unreachable functions (or move them into _test files), and drop the retired options from the web types. Keep the JSON tags only for migration.

## F9. Small helpers implemented more than once in the portal
- Severity: LOW
- Kind: duplicate
- Confidence: HIGH
- Where: server/src/routes/mass.ts:208-232 writes its own worker pool instead of using `eachLimit` (agents/limit.ts). The `agent.update` call with the architecture's sha256 is built three times: routes/agent.ts:50-53, agent-cmd.ts:153, mass.ts:187/215. Versions are compared by two functions: `versionLess` (agents/release.ts:37) and `compareVersions` (wpcore/service.ts:33).
- Scenario: The three `agent.update` copies already differ: one defaults `arch` to amd64 in SQL, one in JS, and one takes `inventory->>'arch'` with `?? 'amd64'` at send time. A future fix, such as refusing an update when the architecture has no hash, will reach only one of them.
- Fix: one `pushAgentUpdate(hub, serverId, inventoryArch)` in agents/release.ts, `eachLimit` in mass.ts, and one version comparator.

## Area summary
- Read: the whole command path on both sides (agents/hub.ts, routes/agent.ts WebSocket, routes/agent-cmd.ts ACTIONS, the MCP `agent()` path, mass.ts, every `hub.command` call site in server/src), the agent's `client.Session` and protocol/messages.go, every handler table in agent/internal/core (`Handlers()` plus the audit, learning, history, score, monthly, firewall, central and intel tables; panel.go is the local panel's separate table), the full settings.go, the web Settings, Firewall and AllowList settings types and save paths, and the portal fleet pushes (trusted, captcha central, mail.global, fleet.set, IPDB sync/apply).
- Contract check: every action the portal sends has an agent handler, and the parameter JSON names match the Go decoders (fw.*, ipdb.*, captcha.*, trusted.apply, mail.global, learning.sample, waf.*, findings.*, the MCP tools). The one web action missing from ACTIONS is F2. Metrics and inventory fields match the TS types.
- Settings keys: every agent settings key is used by web or server, except internal version markers and fields that only fleet pushes write.
- Overall: the contract is mostly consistent. The riskiest spot is `settings.Store.Patch` (F1): it affects every settings save, fleet push and rollback, and fails silently (rules not reapplied, exclusions narrowed). It is followed by F2 (the learned-exclusion approvals are unusable) and the unmasked DQS key (F3).
- Counts: HIGH 2, MEDIUM 4, LOW 3.
