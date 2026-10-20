# FIXED — A8 (web UI)

Web tests: `cd web && npm test` (Node's own test runner, `web/test/*.test.ts`, pure modules only; the web has no DOM test harness). Checks run: `npx tsc --noEmit -p .`, `npx vite build`, `npm test` (19 pass).

F1 | left: portal fixer (server ACTIONS allow-list). Web side checked: Settings » Learned exclusions POSTs `waf.auto_exclusion` with `{ key, action }`, action `accept`/`reject`/`forget`, the same as the agent handler (core.go:1491, learn.go SetAutoExclusion)
F2 | fixed 465e36b | test web/test/requestGate.test.ts (useAgent/useApi reset data, error and loading when server/action/params/path change and drop answers for an old key or older request; Settings and Firewall refuse a save whose data was loaded for another server)
F3 | fixed 465e36b | test web/test/listEdit.test.ts (Settings/Firewall saves rewrite list fields as a delta on a fresh `settings.get`; Allow list and WAF Logs add/remove by value on the current list)
F4 | fixed 5beded9 | test web/test/safeLink.test.ts (ModernOverview, AttackOverview and the bell accept only `page` or `page?query` links). Left for the portal fixer: the same check in server/src/routes/notifications.ts
F5 | fixed 1cbf4b7 | test web/test/zonedInput.test.ts (fleet rollback and bulk restore read and fill `datetime-local` in TIME_ZONE, inputs labelled PKT)
F6 | fixed 465e36b | test: none (UI role gating; no DOM test harness in web/). Operators see only "IP address (everything)" and its Remove; a note says the rest is admin-only
F7 | fixed 4be4de9 | test: none (render-only; tsc + build). CMS sites, Firewall "Server firewalls", AI Scanner and signature status show the error; useApi/useAgent without a path/server stop loading; customers' Settings no longer call /api/ai/status or link to /ai
F8 | fixed 93106be | test: none (render-only; tsc + build). CMS list reloads when a scan ends; scan.report stops polling when finished; scan.list polls 3 s only while a scan runs/waits (30 s otherwise); ServerIPDB skips hidden tabs
F9 | fixed 7730084 | test: none (render-only; tsc + build). Selection is cleared on filter/page/scan change or after an action, otherwise only rows no longer shown are dropped; detail buttons no longer replace the selection
F10 | fixed 976de99 | test: none (render-only; tsc + build). Tags, Remove server and Delete user go through useAction (toast); AddServer takes the baseline before showing a restored token and catches poll errors
F11 | fixed 33211ea | test: none (routing; tsc + build). `<Protected platform>` on the ten master routes, master links hidden for customers, Security Log shown only to admins. Left (server side / owner decision): GET /api/ipdb/whitelist and /api/ipdb/entries are viewer-level, so customers can still read the master IPDB whitelist through the API
F12 | fixed 4d0ed2f | test: none (render-only; tsc + build). Pages through /api/admin/servers; the confirm names every selected server
F13 | fixed 976de99, 33211ea, 6b72df5 | test web/test/validate.test.ts (shared isDomain/isIPorCIDR with range checks). Also: TagEditor merged into ServerListModern, Layout's unused server fetch removed, one countryName, bell `'add'`, dead non-embedded Learning branches removed, Mail's DomainReputation renamed ServerDomainReputation. Left on purpose: the unlinked per-server alias routes (old bookmarks)
