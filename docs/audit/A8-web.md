# A8 — Web UI audit (web/src)

## F1. "Accept / reject learned WAF exclusion" always fails: `waf.auto_exclusion` is not in the portal's agent-action allow-list
- Severity: HIGH
- Kind: contract
- Confidence: HIGH
- Where: web/src/pages/Settings.tsx:1109 (LearnedExclusions onAction) -> server/src/routes/agent-cmd.ts:14-103 (ACTIONS has no `waf.auto_exclusion`); agent handler exists at agent/internal/core/core.go:1491
- Scenario: An admin opens Settings » WAF » Advanced » Learned exclusions and clicks Accept (or Reject/Forget) on a suggested false-positive exclusion. The UI POSTs `/api/servers/:id/agent/waf.auto_exclusion`; agent-cmd.ts finds no ACTIONS entry and answers 404 "unknown action". The admin cannot approve any learned exclusion from the portal, on any server. HANDOFF requires learned exclusions to be switched on only by an admin approving them, so the only approval path is broken fleet-wide (the "suggest" mode can only suggest).
- Fix: add `'waf.auto_exclusion': { role: 'admin', mutates: true, timeoutMs: 180_000 }` to ACTIONS (it runs `WAF.Apply()`, so it needs the longer timeout like `waf.rule`). Add a server test that every action name the web calls through `agentCall`/`useAgent` is present in ACTIONS (a static grep of web/src works) so this cannot drift again.

## F2. Switching servers on a mounted page keeps the previous server's data, and the Settings/Firewall pages then save it to the new server
- Severity: HIGH
- Kind: bug
- Confidence: HIGH
- Where: web/src/components/controls.tsx:33-82 (useAgent), web/src/hooks.ts:5-49 (useApi), web/src/pages/Settings.tsx:279-298, web/src/pages/Firewall.tsx:647-675, web/src/components/ModernLayout.tsx:315-330 (ServerBadge)
- Scenario: React Router reuses the same component when only `:id` changes (`/servers/A/settings` -> `/servers/B/settings`, e.g. from the header bell, whose agent alert link is `settings` (agent/internal/core/extras.go:492), or with browser back/forward). In `useAgent` without `cache`, `ck` is `''` for every server, so the "another server: reset data" branch never runs. `res.data` stays server A's settings. `SettingsPage` only shows the loader when `!res.data`, so it shows A's settings under B's URL. If B is offline or slow, `settings.get` fails, `error` is set, but the error box only shows when `!data`, so A's settings stay on screen with no warning. List editors save the whole list from what is on screen (`whitelist_ips`, `disabled_rules`, `rule_exclusions`, `bot_list`, `ignored_countries`, `blocked_countries`, ddns, `excluded_jails`…). So an admin who adds one IP writes A's whole list plus that IP onto server B. `useAgent` also has no "alive"/request-id guard, and `useApi` sets `alive.current = true` again for the new path, so an A response that arrives after B's overwrites B's data. The header ServerBadge, added so "an action is never taken on the wrong server", keeps showing A's hostname for the same reason.
- Fix: in `useAgent`, key the state on `serverId+action+params` always, not only when caching. Reset `data`/`error`/`loading` whenever that key changes, and drop responses whose key or sequence number is no longer current. Do the same in `useApi` (a per-effect `let live = true` closure in place of the shared `alive` ref, plus clearing data when `path` changes). In SettingsPage/FirewallPage, also reset the local `st`/`fw` copies when `id` changes (or give the page `key={id}` in App.tsx so it remounts). Add a test: render with id A, switch to B with a pending A response, and assert that B never shows A's data.

## F3. List settings are read-modify-write from stale copies, so concurrent edits are lost
- Severity: MEDIUM
- Kind: bug
- Confidence: HIGH
- Where: web/src/pages/AllowList.tsx:55-114 (setList with lists from the page's own `settings.get`), web/src/pages/WAF.tsx:96-102 (disableRule), 312-320 (AllowDialog), web/src/pages/Settings.tsx (ListEditor/RuleExclusionsEditor onChange from `st`), web/src/components/AccountExceptions.tsx:23-36
- Scenario: An admin has Settings » WAF open (loaded at 10:00). At 10:05 they, or another admin, use WAF Logs » "Allow on this site", which adds a rule exclusion. At 10:10 they remove an unrelated exclusion in the Settings tab: `onChange` sends the 10:00 list minus one item, and the 10:05 exclusion is silently deleted. On AllowList, removing a rule exclusion filters by array index `i` from the stale list, so if the list changed in the meantime, a different exclusion is removed. `settings.set` replaces list fields wholesale.
- Fix: send list operations as add/remove deltas (e.g. a `settings.list_edit {section, field, add, remove}` agent action, or `waf.rule_exclusion {add|remove}` keyed by rule+domain+path), or send the version/hash of the list that was read and have the agent reject a stale write (409, then the UI reloads). At minimum, reload `settings.get` right before each list write, as WAF.tsx already does.

## F4. Untrusted agent data is rendered as navigation links in the master's UI (open redirect / phishing)
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: web/src/components/ModernOverview.tsx:87 (`<Link to={a.link}>`), web/src/components/AttackOverview.tsx:48 (`to={sv.link}`)
- Scenario: The agent runs on the customer's server, as the customer's root. A modified agent (or one compromised through the server) returns `dashboard.get` alerts/services with `link: "https://evil.example/login"`. React Router 7 renders an absolute URL as a plain external `<a href>`. The master opens that customer's dashboard (allowed via serverInScope) and clicks "Open →" or a protection chip, and is taken to the attacker's page in the same tab. React 19 blocks `javascript:` URLs, so this is not XSS, but it is a phishing redirect into a page that looks like a portal step. The header bell is safe because it prefixes `/servers/<id>/`.
- Fix: accept only relative in-server links from agents: validate `link` against `/^[a-z0-9-]+(?:\?[A-Za-z0-9=&_-]*)?$/` and fall back to `''` otherwise. Do this both in the UI (one helper used by ModernOverview, AttackOverview and the bell) and when the portal relays alerts (server/src/routes/notifications.ts).

## F5. Date-time inputs are read in the browser's time zone while every time shown is PKT, which shifts fleet rollback and bulk restore windows
- Severity: MEDIUM
- Kind: bug
- Confidence: HIGH
- Where: web/src/pages/FleetHealth.tsx:168-176, web/src/components/BulkFindings.tsx:13-19,65-69; web/src/timezone.ts (installTimeZone patches only the formatting functions)
- Scenario: The portal shows all times in Asia/Karachi (Settings » History, detections, logs). The admin reads "changed at 14:00" there and enters 14:00 in "Roll back settings on every server". `new Date('…T14:00')` is parsed in the browser's zone. In a UTC browser that is 19:00 PKT, so the 5 hours of changes after 14:00 PKT are not undone on any server. With UTC+8 it is 11:00 PKT, so 3 extra hours are undone on every server. The confirm text uses the patched `toLocaleString` and shows a different hour from the one typed. BulkFindings has the same problem: the restore window misses or adds hours of quarantined files, and its default "from" is browser-local.
- Fix: parse and format `datetime-local` values in TIME_ZONE. Add a helper in timezone.ts (`fromZonedInput(v)` / `toZonedInput(unix)`) that builds the timestamp from the calendar fields with the zone offset taken from `Intl.DateTimeFormat(...{timeZone}).formatToParts`, and label the inputs "(PKT)".

## F6. Operators see Allow-list and other admin-only controls that always fail with 403
- Severity: LOW
- Kind: contract
- Confidence: HIGH
- Where: web/src/pages/AllowList.tsx:41,55-57,123-150,170 (`canAct = operator`, writes via `settings.set`, which ACTIONS marks `admin`)
- Scenario: An operator opens Allow list and adds a WAF-only IP, a website, a mail sender, a rule exclusion or a blacklisted-domain exception, or removes one. Every call gets "insufficient permissions". Only kind `ip` (`fw.add`, operator) works. The page says nothing about roles.
- Fix: in AllowList, gate the settings-based kinds and their Remove buttons on `can(user,'admin')` and keep `ip` for operators. Better: show a role note like Settings does.

## F7. Endless spinners when an agent call fails (older agent, offline, timeout)
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: web/src/pages/CMS.tsx:236 (`cms.sites` error never shown), web/src/pages/Firewall.tsx:907 (`fw.meta` "Server firewalls"), web/src/pages/AIScanner.tsx:100 (providers/presets error), 669 (`/api/signatures/status`), web/src/pages/Settings.tsx:589-597 (AISection uses `/api/ai/status`, which is requirePlatform: customers get 403 and see "Checking the portal AI keys…" forever, plus links to the master-only `/ai`), web/src/hooks.ts:24-29 (`useApi(null)` leaves `loading` true forever)
- Scenario: A customer opens Settings » Scanner and the AI box never stops "Checking…". On a server whose agent lacks `fw.meta`, the Firewall page's "Server firewalls" section spins forever. On CMS Threats, a `cms.sites` failure shows a spinner, not the error.
- Fix: render `error` when `!data` in each place listed. In AISection, skip the portal status for non-platform users (`user.platform === false`) and do not link to `/ai`. In useApi, set `loading=false` when `path` is null.

## F8. CMS Threats list never refreshes after a scan finishes; ScanReport and scan list poll forever
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: web/src/pages/CMS.tsx:111-116,221-224; web/src/pages/Scanner.tsx:161 (scan.list every 3 s), 344 (scan.report every 5 s even when completed); web/src/pages/ServerIPDB.tsx:138-140 (ipdb.live every 1 s, no `document.hidden` check)
- Scenario: The user clicks "Scan now" on CMS Threats. `cms.status` polls and the spinner stops, but `cms.sites` is never reloaded, so the table still says "No CMS installations found yet" until a manual reload. A finished scan report keeps sending an agent command every 5 s. An IPDB tab left open in the background sends one agent command per second for as long as it stays open (one per tab per admin, through the portal websocket).
- Fix: reload `list` when `running` changes from true to false. Stop the scan.report interval once status is not running/queued (pass `intervalMs` only while running). Add the `document.hidden` skip to the ServerIPDB loop.

## F9. Scanner Logs selection is wiped by the 15-second poll
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: web/src/pages/Scanner.tsx:416-419 (`useEffect(() => setSel([]), [list.data])` with a 15 s poll); also 691 (`setSel([detail.id])` runs before the confirm)
- Scenario: An operator ticks 20 detections to quarantine. The poll returns a new `list.data` object and every tick is cleared, so selection plus action has to finish within 15 s. Opening a detail and pressing an action button replaces the multi-selection with that one id even when the confirm is cancelled.
- Fix: clear the selection only when the filter, page or scan changes, and otherwise drop ids no longer in `rows`. Remove the `setSel([detail.id])` from the detail buttons.

## F10. Failed actions with no message (unhandled promise rejections)
- Severity: LOW
- Kind: bug
- Confidence: HIGH
- Where: web/src/pages/ServerList.tsx:25 (TagEditor PATCH), web/src/pages/ServerListModern.tsx:110 (Remove server), web/src/pages/Admin.tsx:54 (Delete user), web/src/pages/AddServer.tsx:31-39 (poll interval)
- Scenario: A tag longer than 40 characters, a removal that fails, or a 403 makes `await api()` throw inside an onClick or onSubmit. Nothing is shown, the form stays open, and the console gets an unhandled rejection. AddServer's 4-second poll throws every tick while the portal is unreachable. It also takes its "known servers" baseline only on the first tick after a reloaded pending token, so a server that enrolled before that tick is never reported as joined.
- Fix: wrap these in `useAction().run` (toast on error). In AddServer, take the baseline before showing the token, which `issue()` already does, also for tokens restored by `loadPending`, and catch errors in the poll.

## F11. Customer navigation and route gating rely on the menu only
- Severity: LOW
- Kind: security
- Confidence: MEDIUM
- Where: web/src/App.tsx:93-113 (no platform guard on `/waf-rulesets`, `/captcha-page`, `/ipdb`, `/trusted-services`, `/mail-protection`, `/domain-reputation`, `/ai`, `/learning`, `/appearance`, `/all-servers`); web/src/components/Layout.tsx:113-117 ("Security Log" shown to every role, but the route needs admin); master links on customer-visible pages: web/src/pages/Firewall.tsx:902,1018, web/src/pages/Settings.tsx:597,607,1442, web/src/pages/ServerIPDB.tsx:168
- Scenario: The server enforces requirePlatform on the master routes (verified for captcha, trusted, mail, domainrep, waf-rulesets, waf-intel, ai, learning, appearance), so no master settings leak. But customers who follow those links reach master pages that show only errors. One exception goes beyond the UI: `/ipdb` is reachable, and GET `/api/ipdb/entries` and `/api/ipdb/whitelist` (server/src/routes/ipdb.ts:122,238) are `requireRole('viewer')`, so any customer viewer can read the master's whole IPDB whitelist with notes (the operator's trusted addresses).
- Fix: add a `platform` option to `<Protected>` and use it on the master routes, and hide the links listed above when `user.platform === false`. Make GET `/api/ipdb/whitelist` platform-only (or omit `note`), and decide whether customers may list IPDB entries at all.

## F12. Mass Operations against customers' servers silently stops at 500 servers; confirm lists only visible names
- Severity: LOW
- Kind: failure-mode
- Confidence: HIGH
- Where: web/src/pages/MassOperations.tsx:38 (`/api/admin/servers?per=500`, server max 500, first page only), 67-70
- Scenario: With more than 500 servers fleet-wide, "Customers' servers too" plus "Select all shown" leaves out every server after the first 500 (sorted platform-first, then by hostname), and nothing says so. The confirm dialog builds its name list from the currently filtered `list`, so selected servers that are now filtered out still run but are not named.
- Fix: page through `/api/admin/servers` until `pages`, or add a `per=all` mode for this caller. Build the confirm names from `sel`, not from `list`.

## F13. Duplicate and dead code
- Severity: LOW
- Kind: duplicate
- Confidence: HIGH
- Where:
  - web/src/components/Layout.tsx:32: `useApi('/api/servers/:id')` result is never used, so every server page fetches the server twice (ServerBadge, useServerName and the page fetch it again).
  - web/src/pages/ServerList.tsx: only re-exports ServerListModern plus TagEditor. Merge TagEditor into ServerListModern and point the route at it.
  - `countryName` is defined twice (web/src/pages/Firewall.tsx:22 and web/src/components/WorldMap.tsx:17).
  - The domain regex is defined twice with different rules (AllowList.tsx:33 accepts `-a-.com`, which RuleExclusions.tsx:11 rejects).
  - `isIPorCIDR` (controls.tsx:410) accepts `999.1.1.1/99`.
  - The non-`embedded` branches of AILearning, WafIntel and LearningExport (their own breadcrumb/heading) are unreachable: `/ai-learning`, `/waf-intel` and `/xpguard-learning` redirect into LearningCenter.
  - The per-server aliases `/servers/:id/firewall-logs|waf-logs|bot-attacks|ipdb|ip-reputation|domain-reputation` are not linked anywhere (kept only for old bookmarks).
  - Reputation.tsx (per-server tabs) and DomainReputation.tsx (fleet Safe Browsing key) are not duplicates, but `Mail.tsx` exports another `DomainReputation`, which makes the names confusing. Rename one.
  - The header bell (ModernLayout.tsx:166) excludes `'new'` instead of `'add'`, so on `/servers/add` it queries `?server=add` and labels the result "This server".
- Fix: remove or merge as listed. Use one validation module (domain, IP/CIDR with octet and prefix range checks) shared by AllowList, RuleExclusions and controls.

## Area summary
I read all of web/src: App.tsx, auth.tsx, hooks.ts, api.ts, main.tsx, theme.ts, timezone.ts, noAutofill.ts, format.ts, every component, and every page (Settings, Firewall, Scanner, CMS, WAF, IPDB, ServerIPDB, CaptchaPage, WafRuleSets, AIScanner, MassOperations and the rest). I cross-checked against server/src/routes (route list, ACTIONS allow-list, zod bodies, requirePlatform use) and against the agent handlers and filters for the actions the UI calls. `npx tsc --noEmit -p .` passes.

Overall health: good on XSS. There is no `dangerouslySetInnerHTML`/`innerHTML`, file contents and log lines render as text, all `target=_blank` links have `rel=noreferrer`, React 19 blocks `javascript:` hrefs, secrets come back masked from the agent, and storage accesses are wrapped. Every portal API path the UI calls exists on the server, and all agent actions except one are allow-listed.

Riskiest spots:
1. The missing `waf.auto_exclusion` action (F1) breaks the only admin-approval path for learned WAF exclusions.
2. The data hooks (`useAgent`/`useApi`) keep or race stale data across server switches, and the Settings and Firewall pages write whole lists from that stale state (F2, F3). This can put one server's whitelists or disabled rules on another server.
3. Agent-controlled `link` fields become external links in the master's UI (F4).
4. Time-zone mismatch in fleet rollback and bulk restore (F5).
