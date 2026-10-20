# Audit fixes: brief for every fixer

You fix the findings of one audit report (docs/audit/A*.md) in this
repository. Read `CLAUDE.md` and `docs/HANDOFF.md` (working rules, hard
limits) first.

## How

1. For each finding in your scope, most severe first: re-read the code and
   confirm the finding is real. If it is not (already fixed, wrong reading),
   note "not a bug: why" and move on.
2. Fix it in the engine, for every server and future servers (owner's
   standing rule): no per-site or per-hash workaround. Keep each fix
   minimal and in the style of the surrounding code (comment density,
   naming). No new features, no refactors beyond what the fix needs.
3. Every fix gets a regression test that fails before and passes after,
   with inert fixtures only (no real malware, no exploit payloads, no real
   customer data). Scanner false-positive tests go in
   `agent/internal/scanner/fleetfp_test.go`; other tests next to the code.
4. Run the checks for what you touched:
   - Go: `cd agent && go vet ./... && go test -count=1 ./internal/<pkg>/...`
     (do not run XG_DESTRUCTIVE_TESTS; do not touch iptables/apache).
   - Portal: `service postgresql start` then
     `cd server && npx tsc --noEmit -p . && npx vitest run test/<file>`.
   - Web: `cd web && npx tsc --noEmit -p . && npx vite build`. Never run
     prettier.
5. Commit on your worktree branch in small commits, one finding or a few
   related ones each, message `Audit <report> F<n>: <what changed>` and the
   trailer:
   ```
   Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
   Claude-Session: https://claude.ai/code/session_01RJMHSmaeWWFm3cXTbf4x3Q
   ```
   Do NOT push. Do not bump VERSION. Do not edit docs/AUDIT.md or
   docs/HANDOFF.md (the lead merges and records).
6. Stay inside your scope's files. If a fix needs a file outside it, make
   the smallest change and say so in your report.
7. Do not print secrets or malware content.

## Report back

Write `docs/audit/FIXED-<report>.md` (commit it) with one line per finding:
`F<n> | fixed <commit short sha> | test <name>` or `F<n> | not a bug: …` or
`F<n> | left: why (needs owner decision / too large)`. Your final message:
the branch name and counts fixed / not a bug / left.
