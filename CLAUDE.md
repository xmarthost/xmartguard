# xPGuard

Read `docs/HANDOFF.md` first: it holds the working rules, hard limits,
current state and open items for this project.

Standing rule from the owner (always applies):

- Every fix is for the whole fleet and for future servers. A false
  positive or a wrong block found on one server is fixed in the engine
  (scanner, WAF or firewall logic) so that any server, including new ones
  and fresh scans, handles that kind of file or request correctly, while
  real malware and attacks stay caught. Restoring a file, allow-listing a
  hash or excluding one site is never the whole fix. Every fix gets a
  regression test with an inert fixture (for the scanner:
  `agent/internal/scanner/fleetfp_test.go`).
- No avoidable web server restarts (owner, 2026-11-07). LiteSpeed restarts
  all its processes on every WAF reload and open connections drop
  (ERR_CONNECTION_CLOSED / QUIC errors for customers). Every update must be
  checked for this: nothing may reload the web server per visitor, per pass
  or on a short timer. Write or change WAF rules (and reload) only when it
  is really needed; one reload for a release or a real rule change is fine,
  a continuous stream is not. Prefer address sets (ipset), cookies or files
  read at request time over lists that need a reload.
- Reply to the owner in Roman Urdu.
