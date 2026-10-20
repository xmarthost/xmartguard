# xPGuard full-code audit: brief for every reviewer

Repository: /home/user/xmartguard (read-only for you). xPGuard is a
malware scanner + WAF (ModSecurity rules) + firewall + IPDB blocklist for
cPanel hosting servers (CloudLinux/AlmaLinux, LiteSpeed or Apache). A Go
agent (`agent/`) runs as root on each customer server and keeps a
websocket to the portal (`server/`, Fastify + Postgres, TypeScript). The
portal UI is `web/` (React). Multi-tenant: a master account plus customer
accounts that buy servers; customers must never see other accounts' data
or the master's global settings. Read `docs/HANDOFF.md` for context.

## Your job

Review your assigned area as a senior engineer and security reviewer would
before a "stable" release. Read every file in your area fully, not a
sample. Look for:

1. **Bugs**: wrong logic, races, nil/undefined, error ignored where it
   matters, resource leaks (goroutines, file handles, timers, DB
   connections, unbounded maps/slices/caches growing forever), off-by-one,
   wrong units, timezone, IPv6 handling, panics on bad input.
2. **Security**: injection (shell, SQL, ModSecurity rule, HTML/XSS, path
   traversal, symlink races as root), authz gaps (customer reaching another
   account's server or master-only data/settings), secrets leaking (logs,
   API responses, UI, git), open redirects, SSRF, CSRF, weak crypto,
   missing rate limits, agent commands a portal compromise could abuse
   beyond need, bypasses of WAF/CAPTCHA/firewall.
3. **Failure modes**: what happens when the portal is down, the agent
   restarts mid-operation, the web server reload fails, disk is full, a
   proxy retries a request, 300 servers / 10k domains, LiteSpeed vs Apache.
4. **Duplicate code** worth merging, dead code, options that contradict
   each other.
5. **Contract mismatches** between agent and portal (JSON field names,
   actions, versions) when your area touches them.

## Rules

- Do NOT edit, create or delete any file in the repository. Do not run
  git commands that change state. Do not run destructive tests (no
  XG_DESTRUCTIVE_TESTS, no iptables, no apache restarts). You may run
  read-only commands, `go vet`, `go build`, and non-destructive unit tests.
- Do not contact any real server or external service.
- Never print secrets, keys or malware content in your report.
- Only report findings you verified by reading the code; give the exact
  scenario (input/state -> wrong result). Mark confidence HIGH or MEDIUM;
  drop anything lower. No style nits.

## Output

Write your report to the file named in your task, in this format, most
severe first:

```
## F<n>. <one-line title>
- Severity: CRITICAL | HIGH | MEDIUM | LOW
- Kind: bug | security | leak | failure-mode | duplicate | contract | dead-code
- Confidence: HIGH | MEDIUM
- Where: path/file.go:123 (and others)
- Scenario: concrete input/state -> wrong result
- Fix: the smallest correct fix, engine-level (works for every server)
```

End the file with a short "Area summary" (what you read, overall health,
riskiest spots). Your final message back should be only the path of the
report and the count of findings per severity.
