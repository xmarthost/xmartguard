# A5 fixes (captcha, cms, mail, notify, audit, monitor, panel, sysinfo, layout)

F1 | fixed 139b586 | test TestMachinePathCanonicalOnly, TestSiteRewriteDropsQuery
F2 | fixed f789d8d | test TestSparseWPConfigRefused, TestWordPressChecksSparseConfig
F3 | left: settings.Patch belongs to the other fixer (brief: do not change Settings.Patch)
F4 | left: settings.Patch belongs to the other fixer; the core.go:767 append is outside A5 scope and goes with that fix
F5 | fixed f5da0d6 | test TestOSMLocalScriptAccountFromU
F6 | fixed f5da0d6 | test TestOSMRotatingSendersCounted
F7 | fixed f789d8d | test TestSymlinkedWPConfigSkipped, TestAccountFileOwner
F8 | fixed f789d8d | test TestFIFOInSiteDoesNotBlock
F9 | fixed e88713d | test TestSyncRetriesFailedBind
F10 | fixed ce79541 | test TestRootkitRunConcurrentWithChecks (-race)
F11 | fixed ce79541 | test TestKillChecksStartTime
F12 | fixed ce79541 | test TestRootkitRunConcurrentWithChecks
F13 | fixed 4cfe77c | test TestDoneAndPageUseSafeBack
F14 | fixed 666c739 | test TestAttemptLimitSurvivesFlood, TestChallengeSingleUse
F15 | fixed c0c74bd | test TestCertIndexRebuildInBackground
F16 | fixed fe1471d | test TestSendRecipientHeaderInjection, TestNotificationAddressesValidated
F17 | fixed f5da0d6 | test TestOSMCountersPruned
F18 | fixed 489d75d | test TestCronDetailsMasked
F19 | fixed 1afe362 | test TestApplyWithdrawnCoalesced (WAF apply part only; the full-state save per pass is left: saving less often risks losing passes on a crash, which then withdraws real visitors' cookies, and a delta save needs a store schema change)
F20 | fixed fe1471d | test TestBrandCutByLetters
F21 | fixed 6aba85c | test TestRestoreRefusesOtherDatabase (the "only over the cleaned value" condition needs MySQL to test; TestCleanDBFindingsMySQL covers restore when XG_MYSQL_TEST is set)

## Notes for the lead

- Files outside the A5 scope: `agent/internal/core/central.go` (one call
  changed for F19); `agent/internal/settings/settings.go` (`validate` gets
  the address check for F16, `normalize` cuts the brand by letters for F20;
  `Patch` is not touched).
- F2/F7/F8: one helper, `cms/userfile.go` (O_NOFOLLOW|O_NONBLOCK, regular
  files only, size cap; for wp-config.php also an owner check against the
  account's folders). The audit package now imports cms for it. Behaviour
  change: the DB scan and the WP-Cron override skip a site whose
  wp-config.php is a symlink, or is owned by someone other than the account
  that owns its folders (for example root-owned in a user's folder).
- F1: `/.well-known/` is now limited to acme-challenge, pki-validation,
  cpanel-dcv and security.txt, and the proxied request has no query string.
- F5/F6: a local submission counts against and is held as the account in
  Exim's `U=` when `/var/cpanel/users/<U>` exists. System users (nobody,
  mailnull, root) are counted per sender and owner-mapped as before.
- F9: a failed bind is logged once and retried on the next sync. It is not
  yet shown in the portal's status or health check, because that is core
  wiring outside this scope.
- F14: after a wrong answer the challenge image is used up. The page always
  shows a new image, and TestBuiltinFlow was updated to use it.
- F21: a restore works the cleaned value out again from the saved one. If
  the cleaner's rules change between the clean and the restore, the restore
  is refused instead of overwriting the row.
