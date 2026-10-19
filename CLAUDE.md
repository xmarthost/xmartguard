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
- Reply to the owner in Roman Urdu.
