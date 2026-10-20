# A2 – Scanner audit (agent/internal/scanner, clamdb, ml, wpcore, ai)

Release read: 0.22.26. `go vet` on the five packages is clean. Findings come
from reading the code. Scenarios are kept short; the focus is the defect
and the engine fix.

## F1. replaceLive writes as root to a predictable temp name in a user-owned folder
- Severity: CRITICAL
- Kind: security
- Confidence: HIGH
- Where: agent/internal/scanner/trim.go:250-261; callers trim.go:222, trim.go:288, htaccess.go:526 (automatic from scanner.go:856), core/core.go:1955, core/extras.go:583
- Scenario: the fixed name `.<base>.xg-new` is opened with os.WriteFile and os.Chmod, which follow links, so content written as root can land outside the account.
- Fix: create the temp file relative to a verified dirfd with O_EXCL|O_NOFOLLOW and a random name, use fchown/fchmod on the fd, and renameat. Better, write with the owner's fsuid/fsgid. Add an inert-fixture test with a pre-existing link at the temp name.

## F2. Restore does not pin the path: parent-folder links and chmod-through-link
- Severity: CRITICAL
- Kind: security
- Confidence: HIGH
- Where: actions.go:115-153, actions.go:43-66; reached from core/panel.go:225 (account restore), core/core.go:2007, bulk.go:423
- Scenario: Restore resolves links in parent components, and its final Chmod follows links. The panel `within()` check passes because EvalSymlinks fails on the absent file. A restore can therefore write or chmod outside the account.
- Fix: resolve the path with openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS) from the home, refuse foreign-owned or link parents, create with O_EXCL|O_NOFOLLOW, and use fchmod/fchown. In within(), check the nearest existing parent. Test with a link-swapped parent → error.

## F3. Later actions (quarantine, delete, disable, content view, AI read) use the stored path unpinned
- Severity: HIGH
- Kind: security
- Confidence: HIGH (parents), MEDIUM (final-component races)
- Where: actions.go:69-111, actions.go:156-177, trim.go:321-348, ai/portal.go:121, core/core.go:482
- Scenario: these run long after detection. If the path now resolves elsewhere, the action or read hits a different file than the finding.
- Fix: one helper that opens the finding with O_NOFOLLOW under a verified dirfd and checks the dev/ino/uid recorded at detection; all actions and reads go through it. For AI jobs, read the quarantine copy or a snapshot taken at detection.

## F4. A panel restore by an account is recorded as an administrator's "clean" verdict
- Severity: HIGH
- Kind: security
- Confidence: HIGH
- Where: core/panel.go:225 → core/core.go:2026-2031 (`restoreFinding` saves Source admin); ai/ai.go:397, core/core.go:133 (AdminCleared bypasses Unconfirmed)
- Scenario: an account restoring its own finding clears that content hash server-wide for every account.
- Fix: panel restores must not save a verdict, or must save one scoped to that path and owner with no server-wide clearance.

## F5. The AI verdict is stored under the detection-time hash, but the content is read later from the live path
- Severity: HIGH
- Kind: security
- Confidence: HIGH
- Where: core/core.go:482-483, ai/portal.go:121-125, ai/ai.go:162-163, 300-320
- Scenario: if the file changes between detection and the AI read, a "clean" verdict for different content is saved under the flagged hash. It then auto-restores and clears that hash.
- Fix: hash exactly the bytes sent and drop the verdict when the hash differs from the job's; send the quarantined copy or a detection-time snapshot.

## F6. Name/shape allow-lists return ErrTrusted (no YARA) for content that can still run input
- Severity: HIGH
- Kind: security
- Confidence: HIGH
- Where: scanner/hostingtools.go:79-103 (reToolDanger misses dynamic/variable calls), datafiles.go:36-53 (reL10nCode misses several input sources and callbacks), scanner.go:436-441
- Scenario: a file that matches the expected name and place, passes the token deny-list, but makes a dynamic call on request data is trusted and never scanned further.
- Fix: never return ErrTrusted from shape checks. Use them only to suppress specific heuristic signatures, and still run analyzePHP's input-call rules, the hash DB and YARA. Add fleetfp tests with inert fixtures.

## F7. Whitelist entries without a slash match any file of that basename on the server
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: scanner/scanner.go:388-392
- Scenario: whitelisting a single file by its name exempts every file with that name, on every account.
- Fix: accept only absolute paths and folder prefixes; migrate bare-name entries into explicit paths or drop them with a warning.

## F8. Path-based downgrades: /tests/ and /test/ turn virus into suspicious; PharInclude under /vendor/ is dropped
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: scanner/scanner.go:1493-1509, archive.go:142-146
- Scenario: with the default SuspiciousAction=notify, a backdoor placed under such a folder stays live.
- Fix: downgrade only when the folder belongs to a verified package (Composer/plugin checksums) or the file has library structure; keep strong input-to-exec rules as virus everywhere.

## F9. The scan-engine JSON drops hits for file names that are not valid UTF-8; the YARA scan-list breaks on newlines
- Severity: HIGH
- Kind: bug
- Confidence: HIGH
- Where: scanner/engine.go:349-367 (json.Encoder coerces invalid UTF-8 to U+FFFD), engine.go:277-279 (Lstat fails → hit skipped silently); extra.go:323-345 (newline-separated --scan-list)
- Scenario: full, daily, weekly and new-site scans silently miss such files.
- Fix: send paths as base64 (or []byte) in engineMsg; skip YARA (or use per-file invocation) for names with '\n'; log and count dropped hits.

## F10. Reads after Lstat follow links and are unbounded: hangs or OOM on special files
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: MEDIUM
- Where: scanner.go:425 (os.ReadFile), scanner.go:649-673 (md5File/sha256File), ai/ai.go:345-354 (fileSHA), ai/portal.go:121
- Scenario: if the path becomes a FIFO or a device between stat and read, a realtime worker blocks or reads without limit.
- Fix: open with O_NOFOLLOW|O_NONBLOCK, fstat the fd (regular file, same ino), and read through io.LimitReader(size cap).

## F11. The realtime watch count inflates on directory renames; byPath leaks
- Severity: MEDIUM
- Kind: bug
- Confidence: HIGH
- Where: scanner/realtime.go:500-525, 618-635
- Scenario: inotify returns the existing wd for a renamed folder, but `watches++` runs again and the old byPath key is never removed. The count can reach the limit, after which new folders server-wide fall back to the slow sweep.
- Fix: if the wd is already in dirs, update the mapping without incrementing and delete the old byPath key; add IN_MOVE_SELF handling.

## F12. Realtime addTree runs in the event-reader goroutine; pending is unbounded
- Severity: MEDIUM
- Kind: failure-mode
- Confidence: HIGH
- Where: realtime.go:632-635, 552-591, 697-719
- Scenario: a large tree created or moved in stalls event reading (queue overflow → full catch-up walks), and pending grows without limit.
- Fix: send addTree to a worker goroutine; cap pending and fall back to a catch-up request when it is full.

## F13. The spike guard pauses a signature server-wide on one account's volume
- Severity: MEDIUM
- Kind: security
- Confidence: HIGH
- Where: scanner/spike.go:288-315, scanner.go:832-841
- Scenario: a single account producing more than SpikeLimit hits of one signature stops quarantine of that signature for every account until an admin unpauses it.
- Fix: count per owner and pause only that owner, or exempt hash-DB and high-confidence signatures.

## F14. The comment stripper treats any "<?" as PHP, unlike PHP with short_open_tag=Off
- Severity: MEDIUM
- Kind: security
- Confidence: MEDIUM
- Where: scanner/phplex.go:24-31, heuristics.go:86
- Scenario: the heuristics can blank real code that sits after a non-PHP "<?" (the signature Rules still see raw content).
- Fix: open PHP context only on `<?php`/`<?=` (or run the input-to-exec heuristics on both the raw and the stripped text).

## F15. The WordPress version from the site's version.php is used unvalidated in a cache path and URLs
- Severity: LOW
- Kind: security
- Confidence: HIGH
- Where: wpcore/wpcore.go:146, 262-275, 283-292
- Scenario: a `/` or `..` in the version changes which cache file is read as official checksums.
- Fix: validate the version with `^[0-9][0-9A-Za-z.\-]*$` before use.

## F16. Trimmed and cleaned originals (`<id>.orig`) are never pruned
- Severity: LOW
- Kind: leak
- Confidence: HIGH
- Where: core/extras.go:527-560; scanner/trim.go:234
- Scenario: the quarantine folder grows forever on servers with AutoClean, Trim or WP repair on.
- Fix: include trimmed and cleaned findings in retention (delete their qpath, then the row).

## F17. checkContent (Recheck) duplicates checkFile's content pipeline with differences
- Severity: LOW
- Kind: duplicate
- Confidence: HIGH
- Where: scanner/recheck.go:259-299 vs scanner.go:383-520
- Scenario: Recheck's verdict can differ from a fresh scan's (no cleared/Unconfirmed handling, different order), so "no longer flagged" can be wrong.
- Fix: factor one content-check function used by both.

## Area summary
Read all files in scanner/, clamdb/, ml/, wpcore/ and ai/ (agent side), plus
the callers in core/core.go, core/panel.go and core/extras.go. The detection
engine is in good shape: RE2-only regexes, bounded hex-signature matching
(budget/maxWindow), zip limits, a prefilter that cannot cause misses,
low-priority engine subprocess with group kill. The riskiest spots are the
root file operations on user-owned paths (F1-F3), which need one shared,
link-safe path helper, and the trust/clearance logic (F4-F6), where account
actions and content-shape checks can clear or skip malware server-wide.
